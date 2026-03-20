"""
ZRPC wire encoding/decoding for Blue Protocol (SEA Server).

Frame layout (all big-endian):
  [4]  total length  (includes these 4 bytes)
  [2]  packet_type   bit15=zstd, bits0-14=MessageType
  [8]  service_uuid  = 0x0000000063335342
  [4]  request_id
  [4]  method_id
  [N]  payload       (zstd-compressed if bit15 set)

SEA wrapping: outbound Call payloads must be wrapped with wrap_tag1().
              inbound Return/Notify payloads must be unwrapped with unwrap_tag1().
"""

import asyncio
import struct
import zstandard as zstd

from proto.codec import encode_varint, decode_varint

# ── Constants ─────────────────────────────────────────────────────────────────
SERVICE_UUID   = 0x0000000063335342   # gameplay / scene server UUID

# Gate server (login) uses a different UUID and multiplexed method channel.
# All calls share uuid=GATE_UUID; the inner method is the first 4 bytes of payload.
GATE_UUID                = 0x000000000626ad66
SYNC_UUID                = 0x000000004ebfdf38   # sync service UUID (outer calls interleaved with setup burst)
INNER_METHOD_LOGIN       = b'\x00\x00\x10\x02'   # ConnectWorld inner method prefix
METHOD_LOGIN_RETURN      = 0x0a4e0801             # method_id in gate server's Return — SUCCESS with full session data (confirmed from capture.py 2026-03-17)
METHOD_LOGIN_ERROR       = 0x0a050801             # method_id in gate server's Return — REJECTED (err_code only, minimal payload)

MSG_CALL        = 1
MSG_NOTIFY      = 2
MSG_RETURN      = 3
MSG_SCENE_CALL  = 5   # FrameUp (C→S scene channel)
MSG_FRAME_DOWN  = 6   # FrameDown (S→C scene channel)

ZSTD_FLAG      = 0x8000
TYPE_MASK      = 0x7FFF

HEADER_SIZE    = 22   # 4+2+8+4+4
MIN_FRAME_SIZE = 6    # short keepalive frames (len=10, type=6) are valid but have no header

METHOD_LOGIN   = 0x1002
METHOD_REDIRECT = 3
METHOD_SYNC_NEAR_ENTITIES = 0x06

# ── SEA tag-1 wrapping ────────────────────────────────────────────────────────

def wrap_tag1(inner: bytes) -> bytes:
    """Wrap bytes as protobuf field 1 (tag=0x0A, wire=2). Required for SEA server."""
    return b"\x0a" + encode_varint(len(inner)) + inner


def unwrap_tag1(data: bytes) -> bytes:
    """Peel one field-1 wrapper off inbound payload."""
    if not data or data[0] != 0x0a:
        return data   # not wrapped — return as-is
    length, offset = decode_varint(data, 1)
    return data[offset:offset + length]


# ── Packet encoding ───────────────────────────────────────────────────────────

_zstd_compressor   = zstd.ZstdCompressor(level=1)
_zstd_decompressor = zstd.ZstdDecompressor()

_request_counter = 0

def next_request_id() -> int:
    global _request_counter
    _request_counter = (_request_counter + 1) & 0xFFFFFFFF
    return _request_counter


def encode_packet(method_id: int, payload: bytes, request_id: int | None = None,
                  compress: bool = False) -> bytes:
    """
    Build a complete ZRPC frame for an outbound Call.
    payload must already be wrap_tag1()'d before calling this.
    """
    if request_id is None:
        request_id = next_request_id()

    if compress:
        payload = _zstd_compressor.compress(payload)

    ptype = MSG_CALL | (ZSTD_FLAG if compress else 0)

    body = struct.pack(">HQII", ptype, SERVICE_UUID, request_id, method_id)
    body += payload

    frame = struct.pack(">I", len(body) + 4) + body
    return frame, request_id


def decode_packet(data: bytes) -> dict:
    """
    Parse a complete ZRPC frame (must be exactly one packet, length prefix included).
    Returns dict with keys: total_len, msg_type, compressed, service_uuid,
                            request_id, method_id, payload.
    """
    if len(data) < HEADER_SIZE:
        raise ValueError(f"Packet too short: {len(data)}")

    total_len  = struct.unpack_from(">I", data, 0)[0]
    ptype      = struct.unpack_from(">H", data, 4)[0]
    compressed = bool(ptype & ZSTD_FLAG)
    msg_type   = ptype & TYPE_MASK
    if msg_type == MSG_FRAME_DOWN:
        # FrameDown only has length(4), ptype(2), channel(4)
        svc_uuid   = 0
        request_id = 0
        method_id  = struct.unpack_from(">I", data, 6)[0]  # Actually channel_id, but store it here
        payload    = data[10:total_len]
    else:
        svc_uuid   = struct.unpack_from(">Q", data, 6)[0]
        request_id = struct.unpack_from(">I", data, 14)[0]
        method_id  = struct.unpack_from(">I", data, 18)[0]
        payload    = data[HEADER_SIZE:total_len]

    if compressed:
        with _zstd_decompressor.stream_reader(payload) as rdr:
            payload = rdr.read()

    return {
        "total_len":   total_len,
        "msg_type":    msg_type,
        "compressed":  compressed,
        "service_uuid": svc_uuid,
        "request_id":  request_id,
        "method_id":   method_id,
        "payload":     payload,
    }


# ── Async I/O helpers ─────────────────────────────────────────────────────────

async def read_framed_packet(reader, writer=None) -> bytes:
    """
    Read exactly one ZRPC packet from an asyncio StreamReader.
    Short frames (total_len < HEADER_SIZE) are handled:
      - FrameDown ticks (type=6, 10 bytes) → ACK'd if writer provided
      - Echo (type=4, 6 bytes) → ponged if writer provided
      - Others → discarded
    All short frames loop back to read the next packet.
    """
    import logging
    _log = logging.getLogger(__name__)
    while True:
        header = await reader.readexactly(4)
        total_len = struct.unpack(">I", header)[0]

        if total_len < MIN_FRAME_SIZE or total_len > 0x000FFFFF:
            raise ValueError(f"Invalid packet length: {total_len}")

        body = await reader.readexactly(total_len - 4)

        if total_len >= HEADER_SIZE:
            return header + body

        # ── Handle short frames ──────────────────────────────────
        if len(body) >= 2:
            ptype = struct.unpack_from(">H", body, 0)[0] & TYPE_MASK

            if ptype == MSG_FRAME_DOWN and total_len == 10 and writer is not None:
                # Empty FrameDown tick — ACK with empty FrameUp (same counter)
                seq = struct.unpack_from(">I", body, 2)[0]
                ack = struct.pack(">IHI", 10, MSG_SCENE_CALL, seq)
                try:
                    writer.write(ack)
                    await writer.drain()
                except Exception:
                    pass  # connection lost — let next read raise

            elif ptype == 4 and total_len == 6 and writer is not None:
                # Echo/heartbeat — pong back
                try:
                    writer.write(header + body)
                    await writer.drain()
                except Exception:
                    pass
        # loop back to read next packet


async def send_packet(writer, method_id: int, payload: bytes,
                      request_id: int | None = None, compress: bool = False) -> int:
    """Wrap, frame, and send a single outbound Call packet. Returns request_id."""
    wrapped = wrap_tag1(payload)
    frame, rid = encode_packet(method_id, wrapped, request_id, compress)
    writer.write(frame)
    await writer.drain()
    return rid


def encode_inner_frame(payload: bytes, req_id: int | None = None) -> bytes:
    """
    Build a ZRPC inner frame for embedding inside a FrameUp (C→S type=5) packet.

    Inner frame format (same wire layout as an outer frame):
      [4]  total length
      [2]  packet_type = MSG_CALL (1)
      [8]  uuid        = GATE_UUID  (confirmed from live capture)
      [4]  request_id
      [4]  method_id   = request_id  (mirrors req counter, as observed in captures)
      [N]  payload     (raw — no tag1 wrapping for inner frames)
    """
    if req_id is None:
        req_id = next_request_id()
    body = struct.pack(">HQII", MSG_CALL, GATE_UUID, req_id, req_id) + payload
    return struct.pack(">I", len(body) + 4) + body


def encode_frame_up(channel_id: int, inner_frames: bytes) -> bytes:
    """
    Wrap inner ZRPC frame(s) in a FrameUp (C→S type=5) outer packet.

    Outer format: [4 total_len][2 ptype=5][4 channel_id][inner_frames...]
    """
    body = struct.pack(">HI", MSG_SCENE_CALL, channel_id) + inner_frames
    return struct.pack(">I", len(body) + 4) + body


def _next_frame_up_channel(writer, channel_id=None) -> int:
    """Get the next FrameUp channel ID, auto-incrementing if not specified."""
    if channel_id is not None:
        return channel_id
    ch = getattr(writer, '_frame_up_channel', 1)
    writer._frame_up_channel = ch + 1
    return ch


async def send_frame_up_call(writer, payload: bytes, channel_id: int | None = None) -> int:
    """
    Send a single Call inside a FrameUp outer packet.

    Used for scene-channel calls (e.g. ReqSwitchLine) after login.
    Returns the request_id used for the inner frame.

    If channel_id is None, auto-increments from writer._frame_up_channel.
    Note: inner frame payloads are NOT tag1-wrapped (unlike outer gate calls).
    """
    ch = _next_frame_up_channel(writer, channel_id)
    req_id = next_request_id()
    inner = encode_inner_frame(payload, req_id=req_id)
    frame = encode_frame_up(ch, inner)
    writer.write(frame)
    await writer.drain()
    return req_id


def encode_inner_notify_frame(method_id: int, payload: bytes = b"") -> bytes:
    """
    Build a ZRPC Notify-type inner frame for embedding inside a FrameUp packet.

    Unlike Call inner frames (where method_id mirrors req_id and actual routing
    is done via a 4-byte payload prefix), Notify inner frames carry the actual
    wire method_id in the ZRPC header. request_id is 0 for Notify frames.

    Inner frame format:
      [4]  total length
      [2]  packet_type = MSG_NOTIFY (2)
      [8]  uuid        = GATE_UUID
      [4]  request_id  = 0
      [4]  method_id   = actual wire method ID
      [N]  payload     (raw — no tag1 wrapping)
    """
    body = struct.pack(">HQII", MSG_NOTIFY, GATE_UUID, 0, method_id) + payload
    return struct.pack(">I", len(body) + 4) + body


async def send_frame_up_notify(writer, method_id: int, payload: bytes = b"",
                               channel_id: int | None = None) -> None:
    """
    Send a single Notify inside a FrameUp outer packet.

    Used for scene-channel notifications (e.g. TransferLoadingEnd) where the
    method has no return value (void). The wire method_id goes in the ZRPC header.

    If channel_id is None, auto-increments from writer._frame_up_channel.
    """
    ch = _next_frame_up_channel(writer, channel_id)
    inner = encode_inner_notify_frame(method_id, payload)
    frame = encode_frame_up(ch, inner)
    writer.write(frame)
    await writer.drain()


async def send_frame_up_batch(writer, inner_frames: list[bytes],
                              channel_id: int | None = None) -> None:
    """
    Send multiple inner frames in a single FrameUp outer packet.

    Used when the real client batches several Call/Notify inner frames into
    one FrameUp (e.g. ch=3 has 7 frames in the capture).

    Each item in inner_frames should be a fully-encoded inner frame
    (from encode_inner_frame or encode_inner_notify_frame).
    """
    ch = _next_frame_up_channel(writer, channel_id)
    combined = b"".join(inner_frames)
    frame = encode_frame_up(ch, combined)
    writer.write(frame)
    await writer.drain()


async def send_sync_call(writer, inner_method: bytes, payload: bytes,
                         method_counter: int) -> None:
    """
    Send an outer Call to the sync service (uuid=0x4ebfdf38).

    These are interleaved with FrameUp setup calls in the live capture.
    Uses request_id=0 (observed in capture).
    """
    full_payload = inner_method + payload
    body = struct.pack(">HQII", MSG_CALL, SYNC_UUID, 0, method_counter) + full_payload
    frame = struct.pack(">I", len(body) + 4) + body
    writer.write(frame)
    await writer.drain()


async def drain_ack_frames(reader, writer, timeout: float = 3.0) -> int:
    """
    Read and ACK empty FrameDown channel-open packets for `timeout` seconds.

    After ConnectWorldResult, the server sends ~64 empty FrameDown packets
    to open scene channels. The real client reads and ACKs all of them
    before sending ConfirmLogin.

    Returns the number of frames ACK'd.
    """
    import logging
    _log = logging.getLogger(__name__)
    count = 0
    try:
        async with asyncio.timeout(timeout):
            while True:
                raw = await read_framed_packet(reader, writer=writer)
                count += 1
                # read_framed_packet auto-ACKs short FrameDown packets
                # and only returns full-size packets — if we get one, break
                try:
                    pkt = decode_packet(raw)
                    _log.debug(f"[DrainACK] Got full packet: type={pkt['msg_type']} method={pkt['method_id']:#x}")
                except ValueError:
                    pass
    except (TimeoutError, asyncio.TimeoutError):
        pass
    _log.info(f"[DrainACK] ACK'd {count} packets during channel-open phase")
    return count


async def send_gate_packet(writer, payload: bytes,
                           request_id: int | None = None,
                           inner_method: bytes = INNER_METHOD_LOGIN,
                           outer_method: int = 14,
                           service_uuid: int = GATE_UUID) -> int:
    """
    Send a ZRPC packet to the gate server channel.

    Gate server uses a different UUID and a multiplexed channel scheme:
      - service_uuid  = e.g. GATE_UUID or AUTH_PORT_UUID for early handshakes
      - outer method_id = e.g., 14 for ConnectWorld, 1 for Auth Profile.
      - payload       = inner_method + proto_bytes

    Returns the request_id used.
    """
    if request_id is None:
        request_id = next_request_id()

    inner = inner_method + payload
    ptype = MSG_CALL
    body  = struct.pack(">HQII", ptype, service_uuid, request_id, outer_method) + inner
    frame = struct.pack(">I", len(body) + 4) + body

    writer.write(frame)
    await writer.drain()
    return request_id
