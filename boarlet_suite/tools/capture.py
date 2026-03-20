"""
BPTimer Boarlet Suite — Live Traffic Inspector
===============================================
Run this WHILE IN GAME to extract all config values you need.

What it captures and prints:
  [SERVER]   Gate IP + Port  → config.json gate_ip / gate_port
  [LOGIN]    ConnectWorld payload → slot_N.json fields + JWT token
  [SESSION]  ConnectWorldResult → session_token, connect_guid
  [REDIRECT] NotifyEnterWorld → scene server IP/Port + handover token
  [SWITCH]   Any outbound Call with TransferParam → METHOD_SWITCH_SCENE + scene_id
  [ENTITY]   SyncNearEntities → monster base_ids (confirms Loyal Boarlet = 10904)
  [UNKNOWN]  All other method IDs → helps identify any missing method

Requirements:
  pip install scapy
  Npcap installed: https://npcap.com  (install with "WinPcap API-compatible Mode")
  Run as Administrator (required for raw packet capture on Windows)

Usage:
  cd boarlet_suite
  python tools/capture.py

Output is also saved to tools/capture_output.txt for easy copy-paste.
"""

import sys
import os
import struct
import json
import time
import threading
from collections import defaultdict
from datetime import datetime

# Add parent dir to path so we can import proto/codec.py and core/zrpc.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proto.codec import (
    parse_fields, first_str, first_int, decode_varint,
    decode_connect_world_result, decode_notify_enter_world,
    decode_sync_near_entities,
)

# ── Protocol constants (from constants.rs) ────────────────────────────────────
SERVICE_UUID        = 0x0000000063335342
HEADER_SIZE         = 22
ZSTD_FLAG           = 0x8000
TYPE_MASK           = 0x7FFF

MSG_CALL            = 1
MSG_NOTIFY          = 2
MSG_RETURN          = 3
MSG_SCENE_CALL      = 5   # C→S multiplexed scene-server inner calls
MSG_FRAME_DOWN      = 6

METHOD_LOGIN        = 0x0a4e0801  # ConnectWorld — confirmed from live capture
METHOD_LOGIN_ALT    = 0x1002      # original guess (kept as fallback)
METHOD_REDIRECT     = 3
METHOD_SYNC_NEAR    = 0x06

LOYAL_BOARLET_ID    = 10904

# Server detection signatures (from server_detection in constants.rs)
SERVER_SIGNATURE        = bytes([0x00, 0x63, 0x33, 0x53, 0x42, 0x00])
SERVER_SIGNATURE_OFFSET = 5
LOGIN_RETURN_SIGNATURE  = bytes([
    0x00, 0x00, 0x00, 0x62, 0x00, 0x03, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x11, 0x45, 0x14, 0x00, 0x00,
    0x00, 0x00, 0x0A, 0x4E, 0x08, 0x01, 0x22, 0x24,
])

MAX_PACKET_SIZE = 0x000FFFFF
DEBUG = False   # set True to enable raw-byte tracing

# ── Output setup ──────────────────────────────────────────────────────────────
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "capture_output.txt")
_output_lock = threading.Lock()

def log(msg: str, tag: str = "INFO"):
    ts   = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] [{tag}] {msg}"
    print(line)
    with _output_lock:
        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")

def separator(title: str = ""):
    line = "─" * 60 + (f" {title}" if title else "")
    log(line, "")

# ── TCP stream reassembly ─────────────────────────────────────────────────────

class TcpStream:
    """
    Minimal TCP stream reassembler.
    Tracks one direction of a TCP connection and extracts ZRPC packets.
    """
    def __init__(self, stream_id: str):
        self.stream_id  = stream_id
        self.buffer     = bytearray()
        self.next_seq   = None

    def feed(self, seq: int, payload: bytes) -> list[bytes]:
        """Feed a TCP segment; return any complete ZRPC packets extracted."""
        if not payload:
            return []

        # Ignore all-zero payloads (TCP window probes) — don't advance next_seq.
        # These arrive at the same seq as the real packet that follows and would
        # corrupt the reassembly buffer if accepted.
        if len(payload) <= 8 and all(b == 0 for b in payload):
            return []

        if self.next_seq is None:
            # Bootstrap: look for a valid packet boundary
            if len(payload) >= 4:
                candidate_len = struct.unpack_from(">I", payload, 0)[0]
                if 10 < candidate_len < MAX_PACKET_SIZE:
                    self.next_seq = seq
            if self.next_seq is None:
                return []

        # Handle out-of-order / retransmit segments
        if self.next_seq is not None and seq != self.next_seq:
            diff = (seq - self.next_seq) & 0xFFFFFFFF
            if diff > 0x7FFFFFFF:
                # Retransmit or old segment — discard
                return []
            elif diff > 0x100000:
                # Big gap — connection reset, start fresh
                self.buffer.clear()
                self.next_seq = seq
            else:
                # Small gap — accept anyway and let buffer resync
                self.next_seq = seq

        self.buffer.extend(payload)
        self.next_seq = (seq + len(payload)) & 0xFFFFFFFF
        return self._extract_packets()

    def _extract_packets(self) -> list[bytes]:
        packets = []
        resync_count = 0
        while len(self.buffer) >= 4:
            pkt_len = struct.unpack_from(">I", self.buffer, 0)[0]
            if pkt_len < 6 or pkt_len > MAX_PACKET_SIZE:
                if DEBUG and resync_count < 3:
                    log(
                        f"  [{self.stream_id}] resync: bad pkt_len={pkt_len} "
                        f"buf[0:8]={bytes(self.buffer[:8]).hex()}",
                        "DBG"
                    )
                self.buffer.pop(0)   # resync
                resync_count += 1
                continue
            if len(self.buffer) < pkt_len:
                if DEBUG:
                    log(
                        f"  [{self.stream_id}] partial: need {pkt_len} have {len(self.buffer)}",
                        "DBG"
                    )
                break
            pkt = bytes(self.buffer[:pkt_len])
            del self.buffer[:pkt_len]
            packets.append(pkt)
        if DEBUG and resync_count > 3:
            log(f"  [{self.stream_id}] total resync pops: {resync_count}", "DBG")
        return packets


# ── Stream manager ────────────────────────────────────────────────────────────

class StreamManager:
    def __init__(self):
        self.streams:      dict[str, TcpStream] = {}
        self.server_ips:   set[str]             = set()   # IP only — all ports
        self.seen_methods: set[int]             = set()
        self._lock         = threading.Lock()

    def _stream_key(self, src_ip, src_port, dst_ip, dst_port):
        return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"

    def process_segment(self, src_ip, src_port, dst_ip, dst_port, seq, payload):
        if not payload:
            return

        with self._lock:
            # [HOTFIX] Always treat ports 5003 and 10052 as known server traffic
            if src_port in (5003, 10052):
                self.server_ips.add(src_ip)
            if dst_port in (5003, 10052):
                self.server_ips.add(dst_ip)
                
            is_from_server = src_ip in self.server_ips
            is_to_server   = dst_ip in self.server_ips
            is_known       = is_from_server or is_to_server

            # Try to detect BP server from unknown traffic
            if not is_known:
                if self._detect_server(payload, src_ip, src_port, dst_ip, dst_port):
                    is_from_server = src_ip in self.server_ips
                    is_to_server   = dst_ip in self.server_ips
                    is_known       = is_from_server or is_to_server

            if not is_known:
                return

            direction = "S→C" if is_from_server else "C→S"

            if DEBUG:
                first4 = payload[:4].hex() if len(payload) >= 4 else payload.hex()
                log(
                    f"[{direction}] {src_ip}:{src_port}→{dst_ip}:{dst_port} "
                    f"seq={seq} len={len(payload)} first4={first4}",
                    "DBG"
                )

            key    = self._stream_key(src_ip, src_port, dst_ip, dst_port)
            stream = self.streams.setdefault(key, TcpStream(key))
            packets = stream.feed(seq, payload)

            if DEBUG:
                log(f"  stream={key} extracted={len(packets)} pkt(s)", "DBG")

            for pkt in packets:
                self._handle_packet(pkt, direction, src_ip, src_port, dst_ip, dst_port)

    def _detect_server(self, payload, src_ip, src_port, dst_ip, dst_port) -> bool:
        """Check if payload contains BP server signature."""
        # Login return signature (fixed size)
        if (len(payload) == 0x62 and len(payload) >= 20
                and payload[0:10] == LOGIN_RETURN_SIGNATURE[0:10]
                and payload[14:20] == LOGIN_RETURN_SIGNATURE[14:20]):
            self._register_server(src_ip, src_port, dst_ip, dst_port, payload)
            return True

        # Server UUID signature at known offset
        if len(payload) > 10 and payload[4] == 0:
            data = payload[10:]
            pos  = 0
            while pos + 4 <= len(data):
                pkt_len = struct.unpack_from(">I", data, pos)[0]
                if pkt_len < 4 or pkt_len > len(data) - pos + 4:
                    break
                start = pos + 4
                end   = start + (pkt_len - 4)
                if end <= len(data):
                    sig_start = start + SERVER_SIGNATURE_OFFSET
                    sig_end   = sig_start + len(SERVER_SIGNATURE)
                    if sig_end <= len(data) and data[sig_start:sig_end] == SERVER_SIGNATURE:
                        self._register_server(src_ip, src_port, dst_ip, dst_port, payload)
                        return True
                pos += pkt_len
        return False

    def _register_server(self, src_ip, src_port, dst_ip, dst_port, payload):
        # The BP signature always appears in server→client packets,
        # so src is always the server side.
        server_ip   = src_ip
        server_port = src_port

        if server_ip not in self.server_ips:
            self.server_ips.add(server_ip)
            separator("SERVER DETECTED")
            log(f"gate_ip   = \"{server_ip}\"", "SERVER")
            log(f"gate_port = {server_port}  (first seen — may change per session)", "SERVER")
            log(f"→ Add gate_ip to config.json (port confirmed via LOGIN packet below)", "SERVER")
            separator()

    def _handle_packet(self, data: bytes, direction: str,
                       src_ip, src_port, dst_ip, dst_port):
        if len(data) < 6:
            return
        try:
            ptype    = struct.unpack_from(">H", data, 4)[0]
            msg_type = ptype & TYPE_MASK

            # ── FrameUp (type=5, C→S) and FrameDown (type=6, S→C) ────────────
            # These use a 10-byte outer header: [4 total_len][2 ptype][4 channel_id]
            # Nested ZRPC frames start at data[10:], each with standard [4 len] prefix.
            # Do NOT parse as 22-byte header — uuid/req/method fields don't exist here.
            if msg_type in (MSG_SCENE_CALL, MSG_FRAME_DOWN):
                if len(data) < 10:
                    return
                compressed   = bool(ptype & ZSTD_FLAG)
                channel_id   = struct.unpack_from(">I", data, 6)[0]
                nested_data  = data[10:]
                if compressed:
                    import zstandard as zstd
                    nested_data = zstd.ZstdDecompressor().decompress(nested_data)
                combo = (channel_id, msg_type, 0)
                if combo not in self.seen_methods:
                    self.seen_methods.add(combo)
                    log(
                        f"channel={channel_id:#010x} type={msg_type} "
                        f"dir={direction} nested_len={len(nested_data)}",
                        "FRAME"
                    )
                if msg_type == MSG_FRAME_DOWN:
                    self._unwrap_frame_down(nested_data, direction)
                elif direction == "C→S":
                    self._unwrap_scene_call(nested_data, direction)
                return

            # ── Standard Call / Notify / Return ───────────────────────────────
            if len(data) < HEADER_SIZE:
                if DEBUG:
                    log(f"  short frame msg={msg_type} len={len(data)}", "DBG")
                return

            compressed = bool(ptype & ZSTD_FLAG)
            svc_uuid   = struct.unpack_from(">Q", data, 6)[0]
            request_id = struct.unpack_from(">I", data, 14)[0]
            method_id  = struct.unpack_from(">I", data, 18)[0]
            payload    = data[HEADER_SIZE:]

            if DEBUG:
                log(
                    f"  PKT dir={direction} ptype={ptype:#06x} msg={msg_type} "
                    f"uuid={svc_uuid:#018x} method={method_id:#010x} "
                    f"compressed={compressed} payload_len={len(payload)}",
                    "DBG"
                )

            if compressed:
                import zstandard as zstd
                payload = zstd.ZstdDecompressor().decompress(payload)

            combo = (svc_uuid, msg_type, method_id)
            if combo not in self.seen_methods:
                self.seen_methods.add(combo)
                log(
                    f"uuid={svc_uuid:#018x} "
                    f"type={msg_type} method={method_id:#010x} "
                    f"dir={direction} len={len(payload)}",
                    "METHODS"
                )

            self._dispatch(msg_type, method_id, payload, direction, request_id)

        except Exception:
            pass   # silently skip malformed packets

    def _dispatch(self, msg_type, method_id, payload, direction, request_id):
        # ── ConnectWorld Call (C→S) ────────────────────────────────────────
        # Gate server multiplexes calls: the outer method_id changes per session.
        # Detect by checking the first 4 bytes of the payload for METHOD_LOGIN_ALT (0x1002).
        # _print_connect_world expects the tag-1 wrapped payload (no inner method prefix).
        if msg_type == MSG_CALL:
            inner_method = struct.unpack_from(">I", payload, 0)[0] if len(payload) >= 4 else 0
            if method_id in (METHOD_LOGIN, METHOD_LOGIN_ALT) or inner_method == METHOD_LOGIN_ALT:
                cw_payload = payload[4:] if inner_method == METHOD_LOGIN_ALT else payload
                self._print_connect_world(cw_payload, direction)
                return

        # ── SEA tag-1 unwrap for all other packets ────────────────────────
        if payload and payload[0] == 0x0a:
            try:
                length, offset = decode_varint(payload, 1)
                inner = payload[offset:offset + length]
                if inner:
                    payload = inner
            except Exception:
                pass

        # ── ConnectWorldResult Return (S→C) ───────────────────────────────
        if msg_type == MSG_RETURN and method_id in (METHOD_LOGIN, METHOD_LOGIN_ALT):
            self._print_connect_world_result(payload)

        # ── Server redirect Notify (S→C) ──────────────────────────────────
        elif msg_type == MSG_NOTIFY and method_id == METHOD_REDIRECT:
            self._print_redirect(payload)

        # ── SyncNearEntities Notify (S→C) ─────────────────────────────────
        elif msg_type == MSG_NOTIFY and method_id == METHOD_SYNC_NEAR:
            self._print_entities(payload)

        # ── FrameDown — unwrap and recurse (S→C scene-server batch) ──────
        elif msg_type == MSG_FRAME_DOWN:
            self._unwrap_frame_down(payload, direction)

        # ── SceneCall — unwrap and recurse (C→S scene-server inner calls) ─
        elif msg_type == MSG_SCENE_CALL and direction == "C→S":
            self._unwrap_scene_call(payload, direction)

        # ── Unknown outbound Call ─────────────────────────────────────────
        elif msg_type == MSG_CALL and direction == "C→S":
            # [HOTFIX] Dump the critical DeviceProfile payload in full
            if method_id == 1 and request_id == 0:
                with open("device_profile.bin", "wb") as f:
                    f.write(payload)
                log(f"Saved {len(payload)} bytes of DeviceProfile to device_profile.bin!!", "DUMP")

            self._print_unknown_call(method_id, payload, request_id)



    def _print_connect_world(self, payload: bytes, direction: str):
        try:
            f = parse_fields(payload)
            # unwrap v_request (field 1) — the outer wrapper is ConnectWorld.v_request
            inner_bytes = f.get(1, [b""])[0]
            rf = parse_fields(inner_bytes)

            account_id   = first_str(rf, 1)
            token        = first_str(rf, 3)
            game_version = first_str(rf, 7)
            res_ver      = first_str(rf, 8)
            os_enum      = first_int(rf, 9)

            separator("LOGIN PACKET (ConnectWorld)")
            log(f"direction                = {direction}", "LOGIN")
            log(f"account_id               = \"{account_id}\"", "LOGIN")
            log(f"token (session GUID)     = \"{token}\"", "LOGIN")
            log(f"game_version             = \"{game_version}\"", "LOGIN")
            log(f"client_resource_version  = \"{res_ver}\"", "LOGIN")
            log(f"os_enum                  = {os_enum}", "LOGIN")

            # Raw field dump — helps diagnose if field numbers differ in SEA version
            log("── raw fields in RequestConnectWorld ──", "LOGIN")
            for fnum, vals in sorted(rf.items()):
                for v in vals:
                    if isinstance(v, bytes):
                        try:
                            log(f"  field {fnum} (bytes, len={len(v)}): {v.decode('utf-8', errors='replace')!r}", "LOGIN")
                        except Exception:
                            log(f"  field {fnum} (bytes, len={len(v)}): {v[:64].hex()}", "LOGIN")
                    else:
                        log(f"  field {fnum} (int): {v}", "LOGIN")

            log("", "LOGIN")
            log("→ Copy token to config.json bots[N].token", "LOGIN")
            log("→ For slot_N.json use:", "LOGIN")
            slot = {
                "account_id":              account_id,
                "client_resource_version": res_ver,
                "game_version":            game_version,
                "os_enum":                 os_enum,
            }
            log(json.dumps(slot, indent=2), "LOGIN")
            separator()
        except Exception as e:
            log(f"Parse error: {e} | payload_hex={payload[:64].hex()}", "LOGIN")

    def _print_connect_world_result(self, payload: bytes):
        try:
            r = decode_connect_world_result(payload)
            separator("LOGIN RESULT (ConnectWorldResult)")
            log(f"result         = {r['result']}", "SESSION")
            log(f"err_code       = {r['err_code']}", "SESSION")
            log(f"session_token  = \"{r['session_token']}\"", "SESSION")
            log(f"connect_guid   = \"{r['connect_guid']}\"", "SESSION")
            separator()
        except Exception as e:
            log(f"Parse error: {e}", "SESSION")

    def _print_redirect(self, payload: bytes):
        try:
            d = decode_notify_enter_world(payload)
            separator("SERVER REDIRECT (NotifyEnterWorld, MethodId=3)")
            log(f"scene_ip   = \"{d['scene_ip']}\"", "REDIRECT")
            log(f"scene_port = {d['scene_port']}", "REDIRECT")
            log(f"token      = \"{d['token']}\"  ← handover token", "REDIRECT")
            log(f"line_id    = {d['line_id']}", "REDIRECT")
            separator()
        except Exception as e:
            log(f"Parse error: {e}", "REDIRECT")

    def _print_entities(self, payload: bytes):
        try:
            entities = decode_sync_near_entities(payload)
            if not entities:
                return
            for ent in entities:
                if ent["base_id"] == LOYAL_BOARLET_ID:
                    separator("LOYAL BOARLET DETECTED!")
                    log(f"base_id  = {ent['base_id']}", "ENTITY")
                    log(f"uuid     = {ent['uuid']}", "ENTITY")
                    separator()
        except Exception:
            pass

    def _print_unknown_call(self, method_id: int, payload: bytes, request_id: int):
        # Try to parse as a message with TransferParam nested inside
        # (looks for scene_id in nested field structures)
        scene_id = self._try_extract_scene_id(payload)

        if method_id not in self.seen_methods:
            separator(f"OUTBOUND CALL method_id={method_id:#010x}")
            log(f"method_id  = {method_id} ({method_id:#010x})", "UNKNOWN")
            log(f"request_id = {request_id:#010x}", "UNKNOWN")
            if scene_id is not None:
                log(f"scene_id   = {scene_id}  ← likely ReqSwitchScene!", "UNKNOWN")
                log(f"→ Set METHOD_SWITCH_SCENE = {method_id} in core/scanner.py", "UNKNOWN")
            else:
                log(f"payload hex ({len(payload)} bytes) =", "UNKNOWN")
            for i in range(0, min(len(payload), 256), 32):
                log(f"  {payload[i:i+32].hex()}", "UNKNOWN")
            separator()
        elif scene_id is not None:
            # Quietly log each unique scene_id we see
            log(f"[SWITCH] method={method_id:#010x} scene_id={scene_id}", "SWITCH")

    def _try_extract_scene_id(self, payload: bytes) -> int | None:
        """
        Try to extract scene_id from ReqSwitchScene payload.

        Observed wire format (skip=4 of `00 05 00 02 0a 02 08 XX`):
          field1 → {field1: varint(scene_id)}   ← 2-level nesting only

        Also tries 3-level nesting as a fallback in case structure differs.
        Only call this on MSG_CALL type inner frames to avoid false positives
        from periodic MSG_NOTIFY packets that also embed small integers.

        Pre-filter: both init switches and explicit WL switches are exactly 8 bytes.
        The 11-byte false-positive packet (large scene UUID) is rejected here.
        """
        if len(payload) != 8:
            return None

        for skip in (0, 1, 2, 3, 4):
            try:
                buf = payload[skip:]
                if not buf:
                    continue
                f1 = parse_fields(buf)
                inner1 = f1.get(1, [None])[0]
                if not isinstance(inner1, bytes) or not inner1:
                    continue

                f2 = parse_fields(inner1)

                # 3-level nesting: field1→bytes{field1→bytes{field1/15→int}}
                inner2 = f2.get(1, [None])[0]
                if isinstance(inner2, bytes) and inner2:
                    f3 = parse_fields(inner2)
                    for fnum in (1, 15):
                        val = first_int(f3, fnum)
                        if val >= 1:
                            return val

                # 2-level nesting: field1→bytes{field1/15→int}  ← observed format
                for fnum in (1, 15):
                    val = first_int(f2, fnum)
                    if val >= 1:
                        return val

            except Exception:
                pass
        return None

    def _unwrap_frame_down(self, data: bytes, direction: str):
        """
        Walk nested ZRPC frames inside a FrameDown (S→C type=6).

        `data` is data[10:] of the outer packet — the raw concatenated nested frames.
        Each nested frame: [4 len][2 ptype][8 uuid][4 req_id][4 method_id][N payload]
        """
        pos = 0
        while pos + HEADER_SIZE <= len(data):
            nested_len = struct.unpack_from(">I", data, pos)[0]
            if nested_len < HEADER_SIZE or pos + nested_len > len(data):
                break
            nested = data[pos:pos + nested_len]
            pos += nested_len
            try:
                ptype      = struct.unpack_from(">H", nested, 4)[0]
                compressed = bool(ptype & ZSTD_FLAG)
                msg_type   = ptype & TYPE_MASK
                request_id = struct.unpack_from(">I", nested, 14)[0]
                method_id  = struct.unpack_from(">I", nested, 18)[0]
                payload    = nested[HEADER_SIZE:]

                if compressed:
                    import zstandard as zstd
                    payload = zstd.ZstdDecompressor().decompress(payload)

                # Log all new S→C inner packets (like we do for C→S in _unwrap_scene_call)
                combo = ("scene_down", method_id)
                is_new = combo not in self.seen_methods
                if is_new:
                    self.seen_methods.add(combo)
                    log(
                        f"[scene-down] type={msg_type} method={method_id:#010x} "
                        f"len={len(payload)}",
                        "SCENED"
                    )

                # Check for known handlers first
                if msg_type == MSG_RETURN and method_id in (METHOD_LOGIN, METHOD_LOGIN_ALT):
                    self._print_connect_world_result(payload)
                elif msg_type == MSG_NOTIFY and method_id == METHOD_REDIRECT:
                    self._print_redirect(payload)
                elif msg_type == MSG_NOTIFY and method_id == METHOD_SYNC_NEAR:
                    self._print_entities(payload)
                elif is_new:
                    # Dump all new unknown S→C inner packets
                    separator(f"INNER SCENE-DOWN type={msg_type} method={method_id:#010x}")
                    log(f"payload hex ({len(payload)} bytes) =", "SCENED")
                    for i in range(0, min(len(payload), 128), 32):
                        log(f"  {payload[i:i+32].hex()}", "SCENED")
                    separator()
            except Exception:
                pass

    def _unwrap_scene_call(self, data: bytes, direction: str):
        """
        Walk nested ZRPC frames inside a FrameUp (C→S type=5).

        `data` is data[10:] of the outer packet — the raw concatenated nested frames.
        Each nested frame: [4 len][2 ptype][8 uuid][4 req_id][4 method_id][N payload]
        """
        pos = 0
        while pos + HEADER_SIZE <= len(data):
            nested_len = struct.unpack_from(">I", data, pos)[0]
            if nested_len < HEADER_SIZE or pos + nested_len > len(data):
                break
            nested = data[pos:pos + nested_len]
            pos += nested_len
            try:
                ptype      = struct.unpack_from(">H", nested, 4)[0]
                compressed = bool(ptype & ZSTD_FLAG)
                msg_type   = ptype & TYPE_MASK
                inner_uuid = struct.unpack_from(">Q", nested, 6)[0]
                request_id = struct.unpack_from(">I", nested, 14)[0]
                method_id  = struct.unpack_from(">I", nested, 18)[0]
                payload    = nested[HEADER_SIZE:]

                if compressed:
                    import zstandard as zstd
                    payload = zstd.ZstdDecompressor().decompress(payload)

                combo = ("scene_up", method_id)
                is_new = combo not in self.seen_methods
                if is_new:
                    self.seen_methods.add(combo)
                    log(
                        f"[scene-up] type={msg_type} method={method_id:#010x} "
                        f"uuid={inner_uuid:#018x} len={len(payload)}",
                        "SCENE"
                    )

                # Only check for switch scene in Call-type frames.
                # MSG_NOTIFY inner frames (e.g. heartbeat, position updates) embed small
                # integers that cause false positives if we check them too.
                scene_id = self._try_extract_scene_id(payload) if msg_type == MSG_CALL else None

                if scene_id is not None:
                    separator("SWITCH SCENE DETECTED")
                    log(f"method_id  = {method_id:#010x}", "SWITCH")
                    log(f"inner_uuid = {inner_uuid:#018x}", "SWITCH")
                    log(f"scene_id   = {scene_id}", "SWITCH")
                    log(f"payload    = {payload.hex()}  ({len(payload)} bytes)", "SWITCH")
                    log(f"→ METHOD_SWITCH_SCENE = {method_id:#010x} (sequential — ignore)", "SWITCH")
                    log(f"→ inner_uuid = {inner_uuid:#018x}  ← use this in bot FrameUp", "SWITCH")
                    log(f"→ Add {scene_id} to config.json 'lines'", "SWITCH")
                    separator()
                elif is_new:
                    # Dump all new inner packets (Call or Notify) so nothing is missed
                    separator(f"INNER SCENE PACKET type={msg_type} method={method_id:#010x}")
                    log(f"payload hex ({len(payload)} bytes) =", "INNER")
                    for i in range(0, min(len(payload), 128), 32):
                        log(f"  {payload[i:i+32].hex()}", "INNER")
                    separator()
            except Exception:
                pass


# ── Scapy packet handler ──────────────────────────────────────────────────────

manager = StreamManager()


def _seed_from_config():
    """Pre-populate server_ips from config.json so we don't miss the first C→S login."""
    try:
        cfg_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        gate_ip = cfg.get("gate_ip", "")
        if gate_ip and gate_ip != "192.168.50.123" and not gate_ip.startswith("FILL"):
            manager.server_ips.add(gate_ip)
            log(f"Pre-seeded server IP from config.json: {gate_ip}", "INFO")
            log("→ Login packets will be captured from the very first connection", "INFO")
    except Exception:
        pass  # No config or bad config — detection will auto-find the server


def handle_packet(pkt):
    try:
        from scapy.layers.inet import IP, TCP
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return
        ip  = pkt[IP]
        tcp = pkt[TCP]
        if not tcp.payload:
            return
        raw = bytes(tcp.payload)
        manager.process_segment(
            ip.src, tcp.sport,
            ip.dst, tcp.dport,
            tcp.seq, raw,
        )
    except Exception:
        pass


# ── Entry ─────────────────────────────────────────────────────────────────────

def main():
    # Clear output file
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(f"BPTimer Boarlet Suite — Capture started {datetime.now()}\n\n")

    print("=" * 65)
    print("  BPTimer Boarlet Suite — Live Traffic Inspector")
    print("=" * 65)
    print()
    print("  Capturing Blue Protocol traffic...")
    print("  → Launch the game and log in to see LOGIN details")
    print("  → Switch a World Line to see METHOD_SWITCH_SCENE")
    print(f"  → Output also saved to: {OUTPUT_FILE}")
    print()
    print("  Press Ctrl+C to stop")
    print("=" * 65)
    print()

    _seed_from_config()

    try:
        from scapy.all import sniff
    except ImportError:
        print("ERROR: scapy not installed.")
        print("Run:  pip install scapy")
        print("Also: install Npcap from https://npcap.com")
        sys.exit(1)

    try:
        sniff(
            filter="tcp",
            prn=handle_packet,
            store=False,
        )
    except KeyboardInterrupt:
        print("\n\nStopped.")
        _print_summary()
    except PermissionError:
        print("\nERROR: Permission denied.")
        print("Run this script as Administrator.")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: {e}")
        if "Npcap" in str(e) or "WinPcap" in str(e) or "pcap" in str(e).lower():
            print("Install Npcap from https://npcap.com (enable WinPcap compatible mode)")
        sys.exit(1)


def _print_summary():
    separator("SUMMARY")
    log(f"Method IDs seen: {sorted(manager.seen_methods)}", "SUMMARY")
    log(f"Server pairs: {manager.server_pairs}", "SUMMARY")
    log(f"Full output saved to: {OUTPUT_FILE}", "SUMMARY")
    separator()


if __name__ == "__main__":
    main()
