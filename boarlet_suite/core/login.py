"""
ConnectWorld login flow for Blue Protocol SEA gate server.

Trace format (data/packet_traces/slot_N.json):
{
  "account_id":              "6_XXXXXXXXX",
  "client_resource_version": "0.0.32499.35794",
  "game_version":            "1.0.35794.0",
  "os_enum":                 5
}

The live session token (36-char GUID) comes from config.json bots[N].token.
It must be re-captured each time the bot is restarted.

Gate server protocol differences vs gameplay server:
  - service_uuid = GATE_UUID (0x000000000626ad66)
  - payload = INNER_METHOD_LOGIN prefix + wrap_tag1(ConnectWorld proto)
  - ConnectWorldResult comes back with method_id = METHOD_LOGIN_RETURN (0x0a4e0801)
"""

import asyncio
import json
import logging
import struct
import re

from core.zrpc import (
    METHOD_LOGIN_RETURN, METHOD_LOGIN_ERROR, MSG_RETURN, MSG_NOTIFY,
    read_framed_packet, send_gate_packet, decode_packet, unwrap_tag1, MSG_CALL,
    MSG_FRAME_DOWN, drain_ack_frames, send_frame_up_batch, send_sync_call,
    encode_inner_frame, encode_inner_notify_frame,
)
from proto.codec import (
    encode_connect_world, decode_connect_world_result, parse_fields, first_int,
    encode_confirm_login, encode_field_string, encode_field_varint, encode_field_message,
    encode_setup_burst_initial, encode_setup_burst_relogin,
    encode_fight_value_sync,
)
from core.gate_auth import PORT5003_UUID, _collect_all_strings, _extract_agent_guid

log = logging.getLogger(__name__)

LOGIN_TIMEOUT = 15.0   # seconds to wait for ConnectWorldResult
NOTIFY_ENTER_WORLD_UUID = 0x0000000004a84519

_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)


def load_trace(trace_file: str) -> dict:
    """Load captured login trace from JSON file."""
    with open(trace_file, "r", encoding="utf-8") as f:
        return json.load(f)


async def do_proxy_login(
    writer,
    reader,
    slot_cfg: dict,
    session_blob: str,
    char_id: int,
    lines=None,
) -> dict:
    """
    Perform the SEA Proxy handshake and ConnectWorld login.
    DeviceProfile and Claim packets were already sent by gate_auth on this socket.
    Now we just wait for the proxy to emit the real session token via NotifyEnterWorld.
    """
    handover_token = None
    old_agent_guid = _extract_agent_guid(session_blob)
    
    pkt_count = 0
    try:
        async with asyncio.timeout(LOGIN_TIMEOUT):
            while True:
                raw = await read_framed_packet(reader)
                pkt_count += 1
                try:
                    pkt = decode_packet(raw)
                except ValueError:
                    continue   # short keepalive frame

                log.info(f"[Login] -> msg_type={pkt['msg_type']} method_id={pkt['method_id']:#010x} uuid={pkt['service_uuid']:#018x}")

                if pkt["msg_type"] == MSG_NOTIFY and pkt["service_uuid"] == NOTIFY_ENTER_WORLD_UUID and pkt["method_id"] == 3:
                    inner = unwrap_tag1(pkt["payload"])
                    f = parse_fields(inner)

                    target_host = ""
                    target_port = 0
                    target_uuid = 0
                    
                    try:
                        host_raw = f.get(3, [b""])[0]
                        if host_raw:
                            target_host = host_raw.decode("ascii", "ignore")
                        
                        try:
                            target_port = first_int(f, 4)
                        except:
                            pass
                            
                        with open("notify_fields.txt", "w") as fd:
                            fd.write(f"f keys: {list(f.keys())}\n")
                            for k, val in f.items():
                                try:
                                    fd.write(f"f.{k} int: {first_int(f, k)}\n")
                                except:
                                    pass
                    except Exception as e:
                        pass
                    
                    strings = _collect_all_strings(pkt["payload"])
                    for _, s in strings:
                        if _UUID_RE.fullmatch(s) and s != old_agent_guid:
                            handover_token = s
                            log.info(f"[Login] Found True Handover Token: {handover_token}")
                            break
                    
                    if not handover_token:
                        raise RuntimeError("Login failed: could not extract Handover Token from NotifyEnterWorld")
                    
                    # 4. Now send WorldConnectionType
                    wct_payload = bytes.fromhex("0a150a13576f726c64436f6e6e656374696f6e54797065")
                    await send_gate_packet(
                        writer, wct_payload,
                        request_id=0, inner_method=b'\x00\x00\x00\x15', outer_method=3, service_uuid=PORT5003_UUID
                    )
                    log.info("[Login] Sent WorldConnectionType")
                    
                    # SEA proxy on port 5003 literally ends here! The connection stays open and the client
                    # sends ReqSwitchScene to jump into a real game line server.
                    return {
                        "handover_token": handover_token,
                        "session_token":  "",
                        "connect_guid":   "",
                        "target_host":    target_host,
                        "target_port":    target_port,
                    }

                if pkt["msg_type"] != MSG_RETURN:
                    continue
                    
                if pkt["method_id"] == METHOD_LOGIN_ERROR:
                    err_code = first_int(parse_fields(pkt["payload"]), 2)
                    raise RuntimeError(f"Login rejected by server: err_code={err_code}")

    except TimeoutError:
        raise RuntimeError(f"Login timed out waiting for proxy token (received {pkt_count} packets)")



async def do_scene_login(
    writer,
    reader,
    slot_cfg: dict,
    token_override: str,
    ack_server_sequence: int = 0,
    gate_session_token: str = "",
    scene_id: int = 13,
    is_relogin: bool = False,
    char_id: int = 0,
) -> dict:
    """
    Perform the direct ConnectWorld login for the Scene Server.

    After ConnectWorldResult + ConfirmLogin, sends the post-login setup burst
    (sync calls + initial scene enter) observed in live capture, which tells
    the server we're ready for the game world.

    Returns dict with login result fields plus 'buffered_packets'.
    """
    trace = load_trace(slot_cfg["trace_file"])
    payload = encode_connect_world(
        account_id              = trace["account_id"],
        token                   = token_override,
        game_version            = trace.get("game_version", ""),
        client_resource_version = trace.get("client_resource_version", ""),
        os_enum                 = trace.get("os_enum", 5),
        ack_server_sequence     = ack_server_sequence,
        session_token           = gate_session_token,
    )

    rid = await send_gate_packet(writer, payload)
    log.info(f"[SceneLogin] Sent ConnectWorld request_id={rid:#010x} token={token_override[:8]}\u2026")

    pkt_count = 0
    buffered: list[bytes] = []

    # ── Phase 1: Wait for ConnectWorldResult ─────────────────────────────
    result = None
    try:
        async with asyncio.timeout(LOGIN_TIMEOUT):
            while True:
                raw = await read_framed_packet(reader, writer=writer)
                pkt_count += 1

                try:
                    pkt = decode_packet(raw)
                except ValueError:
                    log.debug(f"[SceneLogin] pkt#{pkt_count}: unparseable ({len(raw)}b)")
                    continue

                log.info(
                    f"[SceneLogin] pkt#{pkt_count}: type={pkt['msg_type']} "
                    f"method={pkt['method_id']:#010x} uuid={pkt['service_uuid']:#018x} "
                    f"payload={len(pkt['payload'])}b"
                )

                if pkt["msg_type"] == MSG_FRAME_DOWN:
                    buffered.append(raw)
                    continue

                if pkt["msg_type"] != MSG_RETURN:
                    continue

                # Check for login error first
                if pkt["method_id"] == METHOD_LOGIN_ERROR:
                    err_code = first_int(parse_fields(pkt["payload"]), 2)
                    raise RuntimeError(f"Scene login rejected by server: err_code={err_code}")

                if pkt["method_id"] == METHOD_LOGIN_RETURN:
                    result = decode_connect_world_result(unwrap_tag1(pkt["payload"]))
                    if result["result"] != 0 or result["err_code"] != 0:
                        raise RuntimeError(
                            f"Scene login failed: result={result['result']} err_code={result['err_code']}"
                        )
                    log.info(
                        f"[SceneLogin] OK \u2014 session={result['session_token'][:12]}\u2026 "
                        f"connect_guid={result['connect_guid'][:12]}\u2026 "
                        f"ack={result['ack_client_sequence']}"
                    )
                    # Log extra fields from ConnectWorldResult for character state
                    try:
                        raw_inner = unwrap_tag1(pkt["payload"])
                        all_fields = parse_fields(raw_inner)
                        extra = {
                            k: v[0] if len(v) == 1 else v
                            for k, v in all_fields.items()
                            if k not in (1, 2, 3, 4, 5)
                        }
                        if extra:
                            extra_log = {}
                            for k, v in extra.items():
                                if isinstance(v, int):
                                    extra_log[f"f{k}"] = v
                                elif isinstance(v, bytes) and len(v) < 80:
                                    try:
                                        extra_log[f"f{k}"] = v.decode("utf-8")
                                    except UnicodeDecodeError:
                                        extra_log[f"f{k}"] = f"0x{v[:32].hex()}"
                                elif isinstance(v, bytes):
                                    extra_log[f"f{k}"] = f"({len(v)}b)"
                            log.info(f"[SceneLogin] ConnectWorldResult extra fields: {extra_log}")
                    except Exception:
                        pass
                    break

                # Unknown MSG_RETURN — dump full hex for debugging.
                raw_hex = raw.hex()
                log.warning(
                    f"[SceneLogin] Unknown RETURN method={pkt['method_id']:#010x}\n"
                    f"  raw packet ({len(raw)}b): {raw_hex}"
                )

                # Small response (< 50 bytes total) is almost certainly an error
                # rejection, not a ConnectWorldResult (which contains UUIDs and
                # is hundreds of bytes). The method_id bytes may actually be the
                # start of the protobuf body if the header format changed.
                # Try parsing the raw bytes after the 6-byte [len+ptype] prefix
                # as protobuf to extract an error code.
                for hdr_size, label in [(22, "std-22"), (18, "gate-18"), (14, "short-14")]:
                    if hdr_size > len(raw):
                        continue
                    candidate = raw[hdr_size:]
                    if not candidate:
                        continue
                    try:
                        fields = parse_fields(candidate)
                        if fields:
                            field_summary = {
                                k: [v.hex() if isinstance(v, bytes) else v for v in vs]
                                for k, vs in fields.items()
                            }
                            log.warning(f"[SceneLogin] Parse@{label}: {field_summary}")
                    except Exception:
                        pass

                # If packet is tiny, treat it as a server rejection — don't wait
                # 15s for a ConnectWorldResult that will never come.
                if len(raw) < 80:
                    raise RuntimeError(
                        f"Scene login rejected: server returned {len(raw)}b "
                        f"(method={pkt['method_id']:#010x}). "
                        f"Game version or device_profile likely stale — "
                        f"run: python main.py refresh"
                    )

                # Larger packet — try parsing as ConnectWorldResult (method_id
                # may have changed after a game patch).
                try:
                    result = decode_connect_world_result(unwrap_tag1(pkt["payload"]))
                    if result.get("session_token"):
                        log.info(
                            f"[SceneLogin] Parsed as ConnectWorldResult despite unexpected method_id! "
                            f"session_token={result['session_token'][:12]}…"
                        )
                        if result["result"] != 0 or result["err_code"] != 0:
                            raise RuntimeError(
                                f"Scene login failed: result={result['result']} err_code={result['err_code']}"
                            )
                        break
                except RuntimeError:
                    raise
                except Exception:
                    log.debug(f"[SceneLogin] Not a ConnectWorldResult, skipping")

    except TimeoutError:
        raise RuntimeError(f"Scene login timed out (received {pkt_count} packets)")

    # ── Phase 2: ConfirmLogin + Setup Burst ──────────────────────────────
    from core.zrpc import send_frame_up_call, send_frame_up_notify

    # Initialize channel counter for this connection
    writer._frame_up_channel = 1

    if not is_relogin:
        # ── Initial login: match capture sequence exactly ──

        # 1. FightValueSyncFromClient (FrameUp ch=1, Notify 0x36001)
        #    First thing the real client sends after ConnectWorldResult.
        fvs_payload = encode_fight_value_sync()
        await send_frame_up_notify(writer, 0x36001, fvs_payload)
        log.info("[SceneLogin] Sent FightValueSyncFromClient (ch=1)")

        # 2. ACK drain — read empty FrameDown channel-open packets.
        #    Real client spends ~5s here; we wait up to 3s.
        await drain_ack_frames(reader, writer, timeout=3.0)

        # 3. ConfirmLogin (outer Call to GATE_UUID)
        confirm_payload = encode_confirm_login(
            agent_guid=token_override, connect_guid=result["connect_guid"]
        )
        confirm_rid = await send_gate_packet(
            writer, confirm_payload, request_id=1,
            inner_method=b'\x00\x00\x60\x03', outer_method=2
        )
        log.info(f"[SceneLogin] Sent ReqConfirmLogin request_id={confirm_rid:#010x}")

        # 4. FrameUp ch=2: Notify 0x5 (entity/timestamp sync — skip, requires entity ID)
        #    Increment channel counter past it to stay aligned with capture.
        writer._frame_up_channel = 3

        # 5. Outer sync calls to 0x4ebfdf38 (methods 4, 5)
        await send_sync_call(writer, b'\x00\x00\x00\x09', b'\x0a\x00', method_counter=4)
        await send_sync_call(writer, b'\x00\x00\x00\x03', b'\x0a\x00', method_counter=5)
        log.info("[SceneLogin] Sent sync calls 4,5 to 0x4ebfdf38")

        # 6. Setup burst batches (ch=3, ch=4, skip ch=5, ch=6)
        batches = encode_setup_burst_initial(scene_id, char_id)
        for i, batch_group in enumerate(batches):
            # Skip ch=5 (entity position sync — requires entity ID we don't have)
            if i == 2:  # Before batch_6
                writer._frame_up_channel = 6
            inner_frames = []
            for payload, is_notify, notify_mid in batch_group:
                if is_notify:
                    inner_frames.append(encode_inner_notify_frame(notify_mid, payload))
                else:
                    inner_frames.append(encode_inner_frame(payload))
            await send_frame_up_batch(writer, inner_frames)

        log.info(
            f"[SceneLogin] Sent {len(batches)} setup batches "
            f"(scene_id={scene_id}, char_id={char_id})"
        )

        # 7. Outer sync calls to 0x4ebfdf38 (methods 6-10)
        await send_sync_call(writer, b'\x00\x00\x00\x0b', b'\x0a\x00', method_counter=6)
        await send_sync_call(writer, b'\x00\x00\x00\x02', b'\x0a\x04\x20\x1e\x10\x01', method_counter=7)
        await send_sync_call(writer, b'\x00\x00\x00\x02', b'\x0a\x04\x20\x1e\x10\x02', method_counter=8)
        await send_sync_call(writer, b'\x00\x00\x00\x02', b'\x0a\x04\x20\x1e\x10\x63', method_counter=9)
        await send_sync_call(writer, b'\x00\x00\x00\x0c', b'\x0a\x00', method_counter=10)
        log.info("[SceneLogin] Sent sync calls 6-10 to 0x4ebfdf38")

    else:
        # ── Re-login: simpler sequence ──

        # 1. Pre-confirm call 0x04d001 (only in relogin)
        await send_frame_up_call(writer, b'\x00\x04\xd0\x01\x0a\x00')
        log.info("[SceneLogin] Sent pre-confirm 0x04d001")

        # 2. ConfirmLogin (outer Call to GATE_UUID)
        confirm_payload = encode_confirm_login(
            agent_guid=token_override, connect_guid=result["connect_guid"]
        )
        confirm_rid = await send_gate_packet(
            writer, confirm_payload, request_id=1,
            inner_method=b'\x00\x00\x60\x03', outer_method=2
        )
        log.info(f"[SceneLogin] Sent ReqConfirmLogin request_id={confirm_rid:#010x}")

        # 3. Setup burst (single batch)
        batches = encode_setup_burst_relogin(scene_id)
        for batch_group in batches:
            inner_frames = []
            for payload, is_notify, notify_mid in batch_group:
                if is_notify:
                    inner_frames.append(encode_inner_notify_frame(notify_mid, payload))
                else:
                    inner_frames.append(encode_inner_frame(payload))
            await send_frame_up_batch(writer, inner_frames)

        log.info(
            f"[SceneLogin] Sent re-login setup burst "
            f"(scene_id={scene_id})"
        )

    # ── Phase 3: Wait for scene data — EnterScene, SyncContainerData ─────
    # The server sends scene data after ConfirmLogin + setup burst.
    # We must wait for it and parse EnterScene (scene_guid + connect_guid)
    # and SyncContainerData (current line_id) to verify we're in-world.
    import struct as _struct
    from proto.codec import decode_enter_scene, decode_sync_container_data
    from core.zrpc import HEADER_SIZE as _HEADER_SIZE

    scene_info = {"scene_guid": "", "connect_guid": "", "line_id": 0}
    SCENE_DRAIN_TIMEOUT = 8.0

    await asyncio.sleep(0.3)
    drain_count = 0
    try:
        async with asyncio.timeout(SCENE_DRAIN_TIMEOUT):
            while True:
                raw2 = await read_framed_packet(reader, writer=writer)
                drain_count += 1
                try:
                    pkt2 = decode_packet(raw2)
                except ValueError:
                    continue

                if pkt2["msg_type"] == MSG_FRAME_DOWN:
                    buffered.append(raw2)
                    # Walk nested frames for diagnostics + state extraction
                    data = pkt2["payload"]
                    pos = 0
                    while pos + _HEADER_SIZE <= len(data):
                        nlen = _struct.unpack_from(">I", data, pos)[0]
                        if nlen < _HEADER_SIZE or pos + nlen > len(data):
                            break
                        nraw = data[pos:pos + nlen]
                        pos += nlen
                        try:
                            npkt = decode_packet(nraw)
                        except ValueError:
                            continue

                        mid = npkt["method_id"]
                        mtype = npkt["msg_type"]
                        payload = npkt["payload"]

                        log.info(
                            f"[SceneDrain] nested: type={mtype} method={mid:#x} "
                            f"payload={len(payload)}b"
                        )

                        # SyncContainerData (0x15) — extract line_id
                        if mtype == MSG_NOTIFY and mid == 0x15 and payload:
                            try:
                                inner = unwrap_tag1(payload)
                                cdata = decode_sync_container_data(inner)
                                if cdata.get("line_id"):
                                    scene_info["line_id"] = cdata["line_id"]
                                log.info(
                                    f"[SceneDrain] SyncContainerData: "
                                    f"char_id={cdata.get('char_id')} "
                                    f"name={cdata.get('name')!r} "
                                    f"line_id={cdata.get('line_id')}"
                                )
                            except Exception as e:
                                log.debug(f"[SceneDrain] SyncContainerData parse error: {e}")

                        # EnterScene — extract scene_guid, connect_guid
                        # Try every Notify with substantial payload
                        if mtype == MSG_NOTIFY and mid not in (0x06, 0x15, 0x16, 0x2B, 0x2D, 0x2E) and payload:
                            try:
                                inner = unwrap_tag1(payload)
                                edata = decode_enter_scene(inner)
                                if edata.get("scene_guid"):
                                    scene_info["scene_guid"] = edata["scene_guid"]
                                    scene_info["connect_guid"] = edata["connect_guid"]
                                    log.info(
                                        f"[SceneDrain] EnterScene: "
                                        f"scene_guid={edata['scene_guid'][:16]}… "
                                        f"connect_guid={edata['connect_guid'][:16]}…"
                                    )
                            except Exception:
                                pass

                        # Return frames — log protobuf fields
                        if mtype == MSG_RETURN and payload:
                            try:
                                inner = unwrap_tag1(payload)
                                fields = parse_fields(inner)
                                field_summary = {}
                                for k, vs in fields.items():
                                    for v in vs[:2]:
                                        if isinstance(v, int):
                                            field_summary[f"f{k}"] = v
                                        elif isinstance(v, bytes) and len(v) < 60:
                                            try:
                                                field_summary[f"f{k}"] = v.decode("utf-8")
                                            except UnicodeDecodeError:
                                                field_summary[f"f{k}"] = f"0x{v[:20].hex()}"
                                        elif isinstance(v, bytes):
                                            field_summary[f"f{k}"] = f"({len(v)}b)"
                                if field_summary:
                                    log.info(f"[SceneDrain] Return method={mid:#x}: {field_summary}")
                            except Exception:
                                pass

                elif pkt2["msg_type"] == MSG_NOTIFY:
                    log.info(
                        f"[SceneDrain] outer Notify: method={pkt2['method_id']:#x} "
                        f"uuid={pkt2['service_uuid']:#018x} payload={len(pkt2['payload'])}b"
                    )
                elif pkt2["msg_type"] == MSG_RETURN:
                    log.info(
                        f"[SceneDrain] outer Return: method={pkt2['method_id']:#x} "
                        f"uuid={pkt2['service_uuid']:#018x} payload={len(pkt2['payload'])}b"
                    )

    except TimeoutError:
        pass

    log.info(
        f"[SceneLogin] Login complete: {len(buffered)} FrameDown, "
        f"{drain_count} total pkts drained, "
        f"line_id={scene_info['line_id']}, "
        f"scene_guid={scene_info['scene_guid'][:16] or '(none)'}…"
    )

    result["buffered_packets"] = buffered
    result["scene_id"] = scene_id
    result["current_line_id"] = scene_info["line_id"]
    result["scene_guid"] = scene_info["scene_guid"]
    result["connect_guid_scene"] = scene_info["connect_guid"]
    return result


