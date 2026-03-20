"""
Gate authentication — exchanges a long-lived JWT for a short-lived session token.

Flow (confirmed from proxy_log.txt 2026-03-17):
  1. JWT captured once via tools/token_proxy.py → saved to config.json["_jwt_auth"]
  2. Before each login, bot connects to auth server on port 5003
  3. Call 1: Bot sends JWT → server responds with player profile + base64 session blob
  4. Call 2: Bot sends session blob back → server acks (session claimed/activated)
  5. Bot decodes base64 blob → extracts agentGuid (36-char UUID)
  6. agentGuid is used as the token in ConnectWorld on port 10052

== First-time setup ==
  Run tools/token_proxy.py, log in normally, then Ctrl+C.
  JWT is saved automatically to config.json → valid for ~7 days.

== Protocol notes (confirmed from proxy_log.txt 2026-03-17) ==

  Call 1 (JWT exchange) — C→S:
    [22-byte ZRPC header: ptype=1, uuid=PORT5003_UUID, req_id=0, method_id=counter]
    [4-byte inner method: 0x00000001]
    [protobuf: field1 → {f23:11, f7:6, f9:version, f5:1001, f4:10, f3:JWT}]

  Call 1 response — S→C:
    [18-byte header: ptype=0x8003 (zstd|RETURN), uuid=echo, req_id=0]
    [zstd-compressed protobuf: player profile with base64 blob at f1.f2.f5]
    Base64 decodes to: { "peerId": N, "accountId": "...", "agentGuid": "UUID", ... }

  Call 2 (claim session) — C→S:
    [22-byte ZRPC header: ptype=1, uuid=PORT5003_UUID, req_id=0, method_id=counter]
    [4-byte inner method: 0x00000003]
    [protobuf: field1 → {field2: base64_blob_string}]

  Call 2 response — S→C:
    [18-byte header: ptype=0x0003 (RETURN)]
    [protobuf: field1 → empty (ack)]
"""

import asyncio
import base64
import json as _json
import logging
import re
import struct
import time
import zstandard as zstd

from proto.codec import (
    encode_field_string, encode_field_message, encode_field_varint,
    parse_fields,
)
from core.zrpc import MSG_CALL, next_request_id

log = logging.getLogger(__name__)

# ── Constants (all confirmed from proxy_log.txt 2026-03-17) ───────────────────

# Service UUID in the outbound ZRPC header for port-5003 auth packets.
PORT5003_UUID = 0x000000004979f6d5

# Port 5003 uses req_id=0 always.
PORT5003_REQ_ID = 0

# Inner method prefixes (4 bytes prepended before the protobuf payload).
PORT5003_INNER_JWT   = b'\x00\x00\x00\x01'   # Call 1: JWT exchange
PORT5003_INNER_CLAIM = b'\x00\x00\x00\x03'   # Call 2: claim/activate session

# Response header length.  S→C packets on port 5003 have NO method_id field:
#   [4 total_len][2 ptype][8 uuid][4 req_id] = 18 bytes, then payload.
PORT5003_RESP_HDR = 18
ZSTD_FLAG = 0x8000

AUTH_PORT    = 5003
AUTH_TIMEOUT = 10.0   # seconds

# Keepalive frame (6 bytes: total_len=6, ptype=4).
# Game exchanges keepalives between Call 1 and Call 2.
KEEPALIVE_FRAME = b'\x00\x00\x00\x06\x00\x04'

_decompressor = zstd.ZstdDecompressor()

_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)


# ── I/O helpers ───────────────────────────────────────────────────────────────

async def _read_auth_packet(reader) -> bytes:
    """Read one port-5003 ZRPC packet, skipping keepalive frames (≤6 bytes)."""
    while True:
        hdr = await asyncio.wait_for(reader.readexactly(4), timeout=AUTH_TIMEOUT)
        plen = struct.unpack(">I", hdr)[0]
        if plen < 6 or plen > 0x000FFFFF:
            raise RuntimeError(f"GateAuth: invalid packet length {plen}")
        body = await asyncio.wait_for(reader.readexactly(plen - 4), timeout=AUTH_TIMEOUT)
        if plen <= 6:
            continue   # keepalive frame — skip
        return hdr + body


# ── Packet building ────────────────────────────────────────────────────────────

def _build_jwt_packet(jwt: str, game_version: str = "1.0.35794.0") -> bytes:
    """
    Build Call 1: JWT exchange packet for port 5003.

    Wire layout (confirmed from proxy_log.txt game packet):
      [22-byte ZRPC header]
      [4-byte inner method: 0x00000001]
      [protobuf: field1 → {f23:11, f7:6, f9:version, f5:1001, f4:10, f3:JWT}]
    """
    method = next_request_id()

    inner = b""
    inner += encode_field_varint(23, 11)
    inner += encode_field_varint(7, 6)
    inner += encode_field_string(9, game_version)
    inner += encode_field_varint(5, 1001)
    inner += encode_field_varint(4, 10)
    inner += encode_field_string(3, jwt)

    payload = PORT5003_INNER_JWT + encode_field_message(1, inner)
    body    = struct.pack(">HQII", MSG_CALL, PORT5003_UUID, PORT5003_REQ_ID, method) + payload
    return struct.pack(">I", len(body) + 4) + body


def _build_claim_packet(session_blob: str, char_id: int = 0) -> bytes:
    """
    Build Call 2: claim/activate session by sending base64 blob back.

    Wire layout (confirmed from proxy_log.txt 2026-03-18, full hex capture):
      [22-byte ZRPC header]
      [4-byte inner method: 0x00000003]
      [protobuf: field1 → {field2: session_blob_string, field3: char_id}]

    The 5 "missing" bytes are field3: charId (varint).
    Example: charId=51817459 → 18f3d7da18 (5 bytes: tag 0x18 + 4-byte varint).
    """
    method = next_request_id()

    inner_msg  = encode_field_string(2, session_blob)
    if char_id:
        inner_msg += encode_field_varint(3, char_id)
    payload   = PORT5003_INNER_CLAIM + encode_field_message(1, inner_msg)
    body      = struct.pack(">HQII", MSG_CALL, PORT5003_UUID, PORT5003_REQ_ID, method) + payload
    return struct.pack(">I", len(body) + 4) + body


# ── Response parsing ───────────────────────────────────────────────────────────

def _collect_all_strings(data: bytes, depth: int = 0, path: str = "") -> list[tuple[str, str]]:
    """Recursively walk protobuf, collecting ALL printable ASCII string fields."""
    results = []
    try:
        fields = parse_fields(data)
    except Exception:
        return results

    for fnum, vals in sorted(fields.items()):
        for v in vals:
            if not isinstance(v, bytes):
                continue

            field_path = f"{path}f{fnum}"

            try:
                s = v.decode("ascii")
                if len(s) >= 4 and all(0x20 <= ord(c) < 0x7F for c in s):
                    results.append((field_path, s))
            except Exception:
                pass

            if depth < 6 and 2 < len(v) <= 16384:
                sub = _collect_all_strings(v, depth + 1, field_path + ".")
                results.extend(sub)

    return results


def _extract_session_blob(raw: bytes) -> str | None:
    """
    Extract the base64 session blob from the Call 1 (JWT exchange) response.

    The blob is at protobuf path f1.f2.f5 and starts with "eyA" (base64 for "{ ").
    It contains JSON: { "peerId": N, "accountId": "...", "agentGuid": "UUID", ... }
    """
    if len(raw) < PORT5003_RESP_HDR:
        return None

    ptype   = struct.unpack_from(">H", raw, 4)[0]
    payload = raw[PORT5003_RESP_HDR:]

    if ptype & ZSTD_FLAG:
        try:
            with _decompressor.stream_reader(payload) as rdr:
                payload = rdr.read()
        except Exception as e:
            log.warning(f"[GateAuth] zstd decompress failed: {e}")
            return None

    log.info(f"[GateAuth] Decompressed {len(payload)} bytes")

    all_strings = _collect_all_strings(payload)
    for field_path, s in all_strings:
        if s.startswith("eyA"):   # base64 for "{ "
            log.info(f"[GateAuth] Session blob at {field_path} ({len(s)} chars)")
            return s

    log.warning(f"[GateAuth] No base64 session blob found in {len(payload)}-byte response. "
                f"All strings:")
    for field_path, s in all_strings:
        log.warning(f"[GateAuth]   {field_path}: {s[:100]!r} ({len(s)} chars)")
    return None


def _extract_char_id(raw: bytes) -> int:
    """
    Extract the charId integer directly from the Call 1 response Protobuf payload.
    The value is located at Protobuf path f1.f2.f7.f1.
    """
    if len(raw) < PORT5003_RESP_HDR:
        return 0

    ptype   = struct.unpack_from(">H", raw, 4)[0]
    payload = raw[PORT5003_RESP_HDR:]

    if ptype & ZSTD_FLAG:
        try:
            with _decompressor.stream_reader(payload) as rdr:
                payload = rdr.read()
        except Exception as e:
            log.warning(f"[GateAuth] zstd decompress failed for charId: {e}")
            return 0

    try:
        f = parse_fields(payload)
        f1 = parse_fields(f.get(1, [b""])[0])
        f2 = parse_fields(f1.get(2, [b""])[0])
        f7_raw = f2.get(7, [b""])[0]
        if f7_raw:
            f7 = parse_fields(f7_raw)
            return f7.get(1, [0])[0]
    except Exception as e:
        log.warning(f"[GateAuth] Failed to extract charId from protobuf: {e}")
    
    return 0


def _decode_session_blob(session_blob: str) -> dict | None:
    """Decode base64 session blob JSON. Returns the full dict."""
    try:
        padding = (4 - len(session_blob) % 4) % 4
        decoded = base64.b64decode(session_blob + "=" * padding)
        return _json.loads(decoded)
    except Exception as e:
        log.warning(f"[GateAuth] Base64/JSON decode failed: {e}")
        return None


def _extract_agent_guid(session_blob: str) -> str | None:
    """Decode base64 session blob JSON and extract the agentGuid UUID."""
    data = _decode_session_blob(session_blob)
    if not data:
        return None
    log.info(f"[GateAuth] Session JSON: {data}")
    for key in ("agentGuid", "sessionGuid", "sessionToken", "token", "guid"):
        val = data.get(key)
        if isinstance(val, str) and _UUID_RE.fullmatch(val):
            log.info(f"[GateAuth] Extracted {key}: {val}")
            return val
    log.warning(f"[GateAuth] No GUID field in session JSON. Keys: {list(data.keys())}")
    return None


# ── Public API ─────────────────────────────────────────────────────────────────

async def get_session_token(auth_ip: str, jwt: str, device_profile: str = "device_profile.bin") -> tuple[str, int, asyncio.StreamReader, asyncio.StreamWriter]:
    """
    Connect to port 5003 and perform the two-step auth handshake:

      Call 1: Send JWT → receive player profile with base64 session blob
      Call 2: Send session blob back → receive ack (session activated)

    Then extract agentGuid from the blob → return as ConnectWorld token.

    Args:
        auth_ip: Real IP of bpm-sea-gamesvr.haoplay.net (config["auth_ip"]).
        jwt:     Long-lived JWT (~7 day validity) from config["_jwt_auth"]["jwt"].

    Returns:
        A tuple of (session_blob: str, char_id: int, reader: StreamReader, writer: StreamWriter) 
        to be used for the remainder of the session.
    """
    log.debug(f"[GateAuth] Connecting to {auth_ip}:{AUTH_PORT}")

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(auth_ip, AUTH_PORT),
            timeout=AUTH_TIMEOUT,
        )
    except Exception as e:
        raise RuntimeError(f"GateAuth: cannot connect to {auth_ip}:{AUTH_PORT}: {e}")

    try:
        # ── Call 1: JWT exchange ──────────────────────────────────────
        # Use the exact capture instead of _build_jwt_packet to bypass anti-cheat
        with open(device_profile, "rb") as f:
            device_profile_inner = f.read()
            
        # The capture file device_profile.bin already contains the inner method prefix.
        # So we just wrap it with the ZRPC outer header.
        method = next_request_id()
        frame1_body = struct.pack(">HQII", MSG_CALL, PORT5003_UUID, PORT5003_REQ_ID, method) + device_profile_inner
        frame1_len  = struct.pack(">I", len(frame1_body) + 4)
        frame1      = frame1_len + frame1_body

        writer.write(frame1)
        await writer.drain()
        log.debug(f"[GateAuth] Sent Extracted JWT packet ({len(frame1)} bytes)")

        resp1 = await _read_auth_packet(reader)
        log.info(f"[GateAuth] JWT response: {len(resp1)} bytes")

        session_blob = _extract_session_blob(resp1)
        if not session_blob:
            log.warning(f"[GateAuth] Raw response hex: {resp1.hex()}")
            raise RuntimeError(
                "GateAuth: no session blob in JWT exchange response. "
                "JWT or device_profile is likely stale — run: python main.py refresh"
            )

        # Extract charId directly from the decompressed protobuf payload
        char_id = _extract_char_id(resp1)
        log.info(f"[GateAuth] Extracted charId from protobuf: {char_id}")

        # ── Keepalive exchange (game does this between Call 1 and Call 2) ──
        for _ in range(1):
            writer.write(KEEPALIVE_FRAME)
            await writer.drain()
            ka = await asyncio.wait_for(reader.readexactly(6), timeout=AUTH_TIMEOUT)
            log.info(f"[GateAuth] Keepalive exchange: {ka.hex()}")

        # ── Call 2: Claim session ─────────────────────────────────────
        frame2 = _build_claim_packet(session_blob, char_id=char_id)
        writer.write(frame2)
        await writer.drain()
        log.info(f"[GateAuth] Sent claim packet ({len(frame2)} bytes, char_id={char_id})")

        resp2 = await _read_auth_packet(reader)
        ack_payload = resp2[PORT5003_RESP_HDR:] if len(resp2) > PORT5003_RESP_HDR else b""
        log.info(f"[GateAuth] Claim ack: {len(resp2)} bytes, payload={ack_payload.hex()}")

        # Check for claim error (success = 0a00, error = 0a03 08XXXX where XX = err_code)
        if ack_payload != b"\x0a\x00":
            try:
                claim_fields = parse_fields(ack_payload)
                inner_bytes = claim_fields.get(1, [b""])[0]
                if isinstance(inner_bytes, bytes) and inner_bytes:
                    inner_fields = parse_fields(inner_bytes)
                    err_code = inner_fields.get(1, [0])[0]
                    raise RuntimeError(f"GateAuth: claim rejected with err_code={err_code}")
                else:
                    log.warning(f"[GateAuth] Claim returned unexpected payload")
            except RuntimeError:
                raise
            except Exception:
                log.warning(f"[GateAuth] Claim returned non-success payload: {ack_payload.hex()}")
        else:
            log.info(f"[GateAuth] Claim SUCCESS")

        # The actual ConnectWorld token is dispensed by port 5003 during 
        # its own sequence, so we just return the setup data along with the open socket.
        return session_blob, char_id, reader, writer

    except Exception:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        raise


def load_jwt(cfg: dict, slot_cfg: dict | None = None) -> str:
    """
    Read saved JWT from config dict. Per-bot JWT takes priority over global.
    Raises RuntimeError if missing or expired.

    JWT is written to config["_jwt_auth"]["jwt"] by tools/token_proxy.py.
    Per-bot: bots[N]["_jwt_auth"]["jwt"] overrides the global JWT.
    """
    # Per-bot JWT takes priority
    if slot_cfg:
        bot_jwt = slot_cfg.get("_jwt_auth", {}).get("jwt", "")
        if bot_jwt:
            jwt_auth = slot_cfg["_jwt_auth"]
            jwt = bot_jwt
        else:
            jwt_auth = cfg.get("_jwt_auth", {})
            jwt = jwt_auth.get("jwt", "")
    else:
        jwt_auth = cfg.get("_jwt_auth", {})
        jwt = jwt_auth.get("jwt", "")
    if not jwt:
        raise RuntimeError(
            "No JWT in config.json._jwt_auth.jwt — "
            "run tools/token_proxy.py and log in once to capture it."
        )
    try:
        parts   = jwt.split(".")
        padding = (4 - len(parts[1]) % 4) % 4
        data    = _json.loads(base64.urlsafe_b64decode(parts[1] + "=" * padding))
        exp     = data.get("exp", 0)
        if exp and int(time.time()) > exp:
            raise RuntimeError(
                f"JWT expired (exp={exp}). "
                "Run tools/token_proxy.py and log in again to refresh it."
            )
    except RuntimeError:
        raise
    except Exception:
        pass   # malformed JWT payload — let the server reject it

    return jwt
