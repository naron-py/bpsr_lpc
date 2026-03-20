"""
World Line scanning loop — full re-authentication state machine.

When switching lines, the server responds to ReqSwitchScene with a
NotifyEnterWorld redirect (MethodId 3) containing a new handover token.
The bot must immediately re-authenticate (ConnectWorld + setup burst)
on the same socket before the server disconnects.

State machine per line switch:
  1. Send ReqSwitchScene
  2. Await NotifyEnterWorld redirect (MethodId 3) — extract new token
  3. Send ConnectWorld with the new handover token
  4. Await ConnectWorldResult
  5. Re-send setup burst (FightValueSync, ConfirmLogin, sync batches)
  6. Scan FrameDown packets for SyncNearEntities (Loyal Boarlet detection)

Protocol confirmed from live capture (2026-03-16):
  - Line switch payload: 00 05 00 02 0a 02 10 <varint(line_id)>
  - Sent inside FrameUp (type=5), inner UUID = GATE_UUID
  - FrameDown outer header is 10 bytes [4 len][2 ptype][4 channel_id];
    nested ZRPC frames start at raw[10:], NOT raw[22:]
"""

import asyncio
import logging
import struct
from dataclasses import dataclass, field

from core.zrpc import (
    METHOD_REDIRECT, METHOD_SYNC_NEAR_ENTITIES,
    MSG_NOTIFY, MSG_RETURN, MSG_FRAME_DOWN, HEADER_SIZE,
    read_framed_packet, send_frame_up_call,
    decode_packet, unwrap_tag1,
)
from core.redirect import parse_redirect, RedirectInfo
from proto.codec import (
    encode_switch_line, decode_sync_near_entities,
    parse_fields, first_int, first_str,
)

log = logging.getLogger(__name__)

# How long to wait for the redirect after sending ReqSwitchScene
REDIRECT_TIMEOUT_SEC = 10.0
# How long to scan for entity data after re-authentication
ENTITY_SCAN_TIMEOUT_SEC = 5.0


class ServerDisconnected(Exception):
    """Raised when the server closes the TCP connection (EOF)."""
    pass


@dataclass
class SwitchResult:
    """Result of a full line-switch cycle."""
    redirect: RedirectInfo | None = None
    # Updated auth state after re-login (only set for same-server redirects)
    new_token: str = ""
    new_session: str = ""
    # True if re-auth was completed by the scanner (same-server redirect)
    reauth_done: bool = False
    # Different-server redirect — caller must open new socket and re-auth
    needs_reconnect: bool = False
    # Buffered FrameDown packets from re-login (already processed for entities)
    buffered_packets: list[bytes] = field(default_factory=list)


async def switch_and_scan(
    reader,
    writer,
    line_id: int,
    boarlet_id: int,
    alert_queue: asyncio.Queue,
    slot_cfg: dict,
    *,
    scene_id: int = 13,
    current_token: str = "",
    gate_session_token: str = "",
) -> SwitchResult:
    """
    Full line-switch state machine: switch -> redirect -> re-auth -> scan.

    For same-server redirects (empty ip/port in NotifyEnterWorld), performs
    the complete re-authentication inline:
      1. Send ReqSwitchScene
      2. Await redirect (extract new handover token)
      3. Send ConnectWorld with new token
      4. Await ConnectWorldResult
      5. Send setup burst (relogin sequence)
      6. Scan for SyncNearEntities

    For different-server redirects (ip/port present), returns immediately
    with needs_reconnect=True so the caller can open a new socket.

    Returns SwitchResult with updated auth tokens and redirect info.
    Raises ServerDisconnected if the connection drops.
    """
    result = SwitchResult()

    # ── Step 1: Send ReqSwitchScene ──────────────────────────────────────
    await _send_switch_line(writer, line_id)

    # ── Step 2: Await redirect ───────────────────────────────────────────
    redirect = await _await_redirect(
        reader, writer, line_id, boarlet_id, alert_queue, slot_cfg,
    )
    result.redirect = redirect

    if redirect is None:
        # No redirect received — unusual, but not fatal.
        # Server may have just sent entity data without a redirect.
        log.warning(f"[Scanner] L{line_id}: No redirect received — line switch may have failed")
        return result

    # ── Step 3: Decide same-server vs different-server ───────────────────
    is_different_server = bool(redirect.ip and redirect.port)

    if is_different_server:
        # Different server — caller must handle the socket reconnection.
        log.info(
            f"[Scanner] L{line_id}: Different-server redirect → "
            f"{redirect.ip}:{redirect.port} (caller handles reconnect)"
        )
        result.needs_reconnect = True
        return result

    # ── Step 4-5: Same-server re-auth (ConnectWorld + setup burst) ───────
    relogin_token = redirect.token or current_token
    log.info(
        f"[Scanner] L{line_id}: Same-server redirect, re-authenticating "
        f"(token={relogin_token[:8]}...)"
    )

    try:
        from core import login
        redir_login = await login.do_scene_login(
            writer, reader, slot_cfg,
            token_override=relogin_token,
            gate_session_token=gate_session_token,
            ack_server_sequence=30,
            scene_id=scene_id,
            is_relogin=True,
        )
    except Exception as e:
        raise ServerDisconnected(
            f"Re-auth failed after redirect on line {line_id}: {e}"
        )

    result.reauth_done = True
    result.new_token = relogin_token
    result.new_session = redir_login.get("session_token", gate_session_token)
    result.buffered_packets = redir_login.get("buffered_packets", [])

    log.info(f"[Scanner] L{line_id}: Re-auth complete, scanning for entities...")

    # ── Step 6: Process buffered packets from re-login for entities ──────
    for raw_pkt in result.buffered_packets:
        try:
            pkt = decode_packet(raw_pkt)
            if pkt["msg_type"] == MSG_FRAME_DOWN:
                _handle_frame_down_raw(
                    pkt["payload"], boarlet_id, alert_queue, slot_cfg, line_id,
                )
        except _RedirectInFrameDown:
            pass  # ignore nested redirects in buffered data
        except Exception:
            pass

    # ── Step 6b: Continue scanning for additional entity data ────────────
    await _scan_entities(
        reader, writer, line_id, boarlet_id, alert_queue, slot_cfg,
    )

    return result


# ── Internal helpers ──────────────────────────────────────────────────────────

async def _send_switch_line(writer, line_id: int) -> None:
    """Send ReqSwitchLine inside a FrameUp inner frame."""
    payload = encode_switch_line(line_id)
    await send_frame_up_call(writer, payload)
    log.debug(f"[Scanner] SwitchLine -> line_id={line_id}")


async def _await_redirect(
    reader, writer, line_id: int,
    boarlet_id: int, alert_queue: asyncio.Queue, slot_cfg: dict,
) -> RedirectInfo | None:
    """
    Wait for the NotifyEnterWorld redirect after sending ReqSwitchScene.

    Also processes any SyncNearEntities or FrameDown that arrive before
    the redirect (the server may send entity data for the current line
    before the redirect kicks in).

    Returns RedirectInfo if found, None on timeout.
    Raises ServerDisconnected on EOF.
    """
    pkt_count = 0
    deadline = asyncio.get_event_loop().time() + REDIRECT_TIMEOUT_SEC

    while asyncio.get_event_loop().time() < deadline:
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            break

        try:
            async with asyncio.timeout(remaining):
                raw = await read_framed_packet(reader, writer=writer)
        except TimeoutError:
            break
        except asyncio.IncompleteReadError:
            raise ServerDisconnected(f"EOF while awaiting redirect on line {line_id}")
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
            raise ServerDisconnected(f"Connection lost on line {line_id}: {e}")

        pkt_count += 1

        try:
            pkt = decode_packet(raw)
        except ValueError:
            continue

        # ── Redirect found — return immediately ──
        if pkt["msg_type"] == MSG_NOTIFY and pkt["method_id"] == METHOD_REDIRECT:
            log.info(f"[Scanner] L{line_id}: Redirect received (pkt#{pkt_count})")
            return parse_redirect(pkt["payload"])

        # ── FrameDown — check for nested redirect or entity data ──
        if pkt["msg_type"] == MSG_FRAME_DOWN:
            log.info(
                f"[Scanner] L{line_id}: FrameDown pkt#{pkt_count} "
                f"channel={pkt['method_id']:#x} payload={len(pkt['payload'])}b"
            )
            try:
                _handle_frame_down_raw(
                    pkt["payload"], boarlet_id, alert_queue, slot_cfg, line_id,
                )
            except _RedirectInFrameDown as e:
                log.info(f"[Scanner] L{line_id}: Redirect (in FrameDown) received (pkt#{pkt_count})")
                return e.redirect

        # ── Return — possibly the response to our SwitchScene call ──
        elif pkt["msg_type"] == MSG_RETURN:
            log.info(
                f"[Scanner] L{line_id}: Return pkt#{pkt_count} "
                f"method={pkt['method_id']:#x} uuid={pkt['service_uuid']:#018x} "
                f"payload={len(pkt['payload'])}b"
            )
            if pkt["payload"]:
                try:
                    inner = unwrap_tag1(pkt["payload"])
                    fields = parse_fields(inner)
                    field_summary = {}
                    for k, vs in fields.items():
                        for v in vs[:3]:
                            if isinstance(v, int):
                                field_summary[f"f{k}"] = v
                            elif isinstance(v, bytes) and len(v) < 80:
                                try:
                                    field_summary[f"f{k}"] = v.decode("utf-8")
                                except UnicodeDecodeError:
                                    field_summary[f"f{k}"] = f"0x{v[:32].hex()}"
                            elif isinstance(v, bytes):
                                field_summary[f"f{k}"] = f"({len(v)}b)"
                    log.info(f"[Scanner] L{line_id}: Return fields: {field_summary}")
                except Exception:
                    log.info(f"[Scanner] L{line_id}: Return raw={pkt['payload'][:64].hex()}")

        # ── Standalone Notify — check for entity data ──
        elif pkt["msg_type"] == MSG_NOTIFY:
            _handle_notify(pkt, boarlet_id, alert_queue, slot_cfg, line_id)

    if pkt_count == 0:
        log.warning(
            f"[Scanner] L{line_id}: 0 packets in {REDIRECT_TIMEOUT_SEC}s "
            f"(server sent nothing after SwitchScene)"
        )
    else:
        log.warning(f"[Scanner] L{line_id}: {pkt_count} packets, but no redirect found")

    return None


async def _scan_entities(
    reader, writer, line_id: int,
    boarlet_id: int, alert_queue: asyncio.Queue, slot_cfg: dict,
) -> None:
    """
    After re-authentication, scan incoming FrameDown packets for
    SyncNearEntities to detect Loyal Boarlet spawns.

    Runs for ENTITY_SCAN_TIMEOUT_SEC or until no more data arrives.
    """
    pkt_count = 0
    deadline = asyncio.get_event_loop().time() + ENTITY_SCAN_TIMEOUT_SEC

    while asyncio.get_event_loop().time() < deadline:
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            break

        try:
            async with asyncio.timeout(remaining):
                raw = await read_framed_packet(reader, writer=writer)
        except TimeoutError:
            break
        except asyncio.IncompleteReadError:
            # EOF during entity scan — connection may be closing.
            # Not fatal since re-auth already succeeded.
            log.debug(f"[Scanner] L{line_id}: EOF during entity scan (non-fatal)")
            break
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            log.debug(f"[Scanner] L{line_id}: Connection reset during entity scan (non-fatal)")
            break

        pkt_count += 1

        try:
            pkt = decode_packet(raw)
        except ValueError:
            continue

        if pkt["msg_type"] == MSG_FRAME_DOWN:
            try:
                _handle_frame_down_raw(
                    pkt["payload"], boarlet_id, alert_queue, slot_cfg, line_id,
                )
            except _RedirectInFrameDown:
                pass  # ignore unexpected redirect during scan phase

        elif pkt["msg_type"] == MSG_NOTIFY:
            _handle_notify(pkt, boarlet_id, alert_queue, slot_cfg, line_id)

    if pkt_count > 0:
        log.info(f"[Scanner] L{line_id}: Scanned {pkt_count} entity packets after re-auth")


def _handle_notify(pkt: dict, boarlet_id: int, queue: asyncio.Queue,
                   slot_cfg: dict, line_id: int) -> None:
    if pkt["method_id"] != METHOD_SYNC_NEAR_ENTITIES:
        return
    _parse_entities(pkt["payload"], boarlet_id, queue, slot_cfg, line_id)


def _handle_frame_down_raw(data: bytes, boarlet_id: int, queue: asyncio.Queue,
                            slot_cfg: dict, line_id: int) -> None:
    """
    Walk nested ZRPC frames inside a FrameDown payload.

    `data` is pkt["payload"] (already decompressed) — raw concatenated
    inner ZRPC frames. Each inner frame starts with a 4-byte length prefix.
    """
    pos = 0
    frame_count = 0
    method_counts: dict[int, int] = {}
    while pos + HEADER_SIZE <= len(data):
        nested_len = struct.unpack_from(">I", data, pos)[0]
        if nested_len < HEADER_SIZE or pos + nested_len > len(data):
            break
        nested_raw = data[pos:pos + nested_len]
        pos += nested_len
        frame_count += 1
        try:
            nested = decode_packet(nested_raw)
            mid = nested["method_id"]
            method_counts[mid] = method_counts.get(mid, 0) + 1

            if nested["msg_type"] == MSG_NOTIFY and mid == METHOD_REDIRECT:
                raise _RedirectInFrameDown(parse_redirect(nested["payload"]))
            if nested["msg_type"] == MSG_NOTIFY:
                _handle_notify(nested, boarlet_id, queue, slot_cfg, line_id)

            # Dump unknown nested frames for diagnostics
            if mid not in (METHOD_REDIRECT, METHOD_SYNC_NEAR_ENTITIES):
                payload_hex = nested["payload"][:64].hex() if nested["payload"] else "(empty)"
                log.info(
                    f"[Scanner] L{line_id} nested: type={nested['msg_type']} "
                    f"method={mid:#x} uuid={nested['service_uuid']:#018x} "
                    f"payload({len(nested['payload'])}b)={payload_hex}"
                )
                # Try protobuf parse for any Return-type responses
                if nested["msg_type"] == MSG_RETURN and nested["payload"]:
                    try:
                        from proto.codec import parse_fields, first_int, first_str
                        from core.zrpc import unwrap_tag1
                        inner_data = unwrap_tag1(nested["payload"])
                        fields = parse_fields(inner_data)
                        field_summary = {}
                        for k, vs in fields.items():
                            for v in vs:
                                if isinstance(v, int):
                                    field_summary[f"f{k}"] = v
                                elif isinstance(v, bytes) and len(v) < 60:
                                    try:
                                        field_summary[f"f{k}"] = v.decode("utf-8")
                                    except UnicodeDecodeError:
                                        field_summary[f"f{k}"] = v.hex()
                                elif isinstance(v, bytes):
                                    field_summary[f"f{k}"] = f"({len(v)}b)"
                        log.info(f"[Scanner] L{line_id} nested Return fields: {field_summary}")
                    except Exception:
                        pass
        except _RedirectInFrameDown:
            raise
        except Exception as e:
            log.debug(f"[Scanner] FrameDown nested frame parse error: {e}")

    if frame_count > 0:
        methods_str = ", ".join(f"{m:#x}:{c}" for m, c in sorted(method_counts.items()))
        log.info(
            f"[Scanner] L{line_id} FrameDown: {frame_count} nested frames, "
            f"{len(data)}b decompressed, methods=[{methods_str}]"
        )


class _RedirectInFrameDown(Exception):
    """Signals a redirect found inside a FrameDown batch."""
    def __init__(self, redirect: RedirectInfo):
        self.redirect = redirect


def _parse_entities(payload: bytes, boarlet_id: int, queue: asyncio.Queue,
                    slot_cfg: dict, line_id: int) -> None:
    try:
        entities = decode_sync_near_entities(unwrap_tag1(payload))
    except Exception as e:
        log.warning(f"[Scanner] SyncNearEntities parse error: {e}")
        return

    if entities:
        base_ids = [e["base_id"] for e in entities[:10]]
        log.info(
            f"[Scanner] L{line_id}: {len(entities)} monsters found, "
            f"base_ids(first 10)={base_ids}"
        )

    for ent in entities:
        if ent["base_id"] == boarlet_id:
            from alerts.discord import Alert
            alert = Alert(
                boarlet_id = boarlet_id,
                line_id    = line_id,
                slot_id    = slot_cfg["slot"],
                spawn_name = slot_cfg["spawn_name"],
            )
            try:
                queue.put_nowait(alert)
                log.info(
                    f"[Scanner] Loyal Boarlet found! "
                    f"line={line_id} slot={slot_cfg['slot']} "
                    f"loc={slot_cfg['spawn_name']}"
                )
            except asyncio.QueueFull:
                pass
