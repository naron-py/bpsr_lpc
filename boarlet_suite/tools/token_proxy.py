"""
Token Proxy — intercepts port 5003 (JWT auth), extracts the JWT token,
forwards to real server, and logs the response to discover session UUID format.

Phase 1: Run this proxy, log in once → JWT extracted and saved (valid ~7 days)
Phase 2: Bot uses saved JWT to authenticate independently on port 5003

== Setup ==
Hosts file (C:\Windows\System32\drivers\etc\hosts), open Notepad as Admin:
    127.0.0.1 bpm-sea-gamesvr.haoplay.net

== Usage ==
    python tools/token_proxy.py
Then launch the game and log in normally.
"""

import asyncio
import base64
import json
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from proto.codec import parse_fields, first_str

PROXY_HOST      = "0.0.0.0"
PROXY_PORT      = 5003
REAL_SERVER_IP  = "172.65.161.68"   # real IP of bpm-sea-gamesvr.haoplay.net (bypass hosts)
REAL_SERVER_PORT = 5003

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json")
LOG_PATH    = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxy_log.txt")

_log_file = None


def _log(msg: str):
    ts = time.strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    if _log_file:
        _log_file.write(line + "\n")
        _log_file.flush()


def _try_extract_jwt(raw: bytes) -> str | None:
    """Extract JWT from the game's port-5003 ZRPC-framed packet."""
    if len(raw) < 22:
        return None
    payload = raw[22:]           # skip ZRPC header
    outer = parse_fields(payload)
    inner_bytes = outer.get(1, [b""])[0]
    if not inner_bytes:
        return None
    inner = parse_fields(inner_bytes)
    jwt_bytes = inner.get(3, [b""])[0]
    if not jwt_bytes:
        return None
    try:
        jwt = jwt_bytes.decode("ascii")
        if jwt.startswith("eyJ") and jwt.count(".") >= 2:
            return jwt
    except Exception:
        pass
    return None


def _decode_jwt_expiry(jwt: str) -> tuple[int, str]:
    """Return (exp_timestamp, human_readable_remaining)."""
    try:
        parts = jwt.split(".")
        payload_b64 = parts[1]
        padding = (4 - len(payload_b64) % 4) % 4
        decoded = base64.urlsafe_b64decode(payload_b64 + "=" * padding)
        data = json.loads(decoded)
        exp  = data.get("exp", 0)
        uid  = data.get("uid", "?")
        remaining = max(0, exp - int(time.time()))
        days  = remaining // 86400
        hours = (remaining % 86400) // 3600
        return exp, uid, f"{days}d {hours}h"
    except Exception as e:
        return 0, "?", f"(parse error: {e})"


def _save_jwt(jwt: str, uid):
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    cfg.setdefault("_jwt_auth", {})
    cfg["_jwt_auth"]["jwt"]         = jwt
    cfg["_jwt_auth"]["captured_at"] = int(time.time())
    cfg["_jwt_auth"]["uid"]         = str(uid)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def _analyze_response(raw: bytes):
    """Log everything about the server's port-5003 response."""
    _log(f"Response total: {len(raw)} bytes")
    _log(f"Response hex (first 256): {raw[:256].hex()}")
    _log(f"Response ASCII (first 128): {raw[:128]!r}")

    if len(raw) < 22:
        return

    ptype      = struct.unpack_from(">H", raw, 4)[0]
    uuid       = struct.unpack_from(">Q", raw, 6)[0]
    request_id = struct.unpack_from(">I", raw, 14)[0]
    method_id  = struct.unpack_from(">I", raw, 18)[0]
    payload    = raw[22:]

    _log(f"  ptype={ptype:#06x} uuid={uuid:#018x} req_id={request_id} method={method_id:#010x}")
    _log(f"  payload ({len(payload)} bytes): {payload[:128].hex()}")

    # Try to find UUID-like strings (session token)
    try:
        text = raw.decode("latin-1")
        import re
        uuids = re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text, re.I)
        if uuids:
            _log(f"  *** UUID strings found in response: {uuids}")
        else:
            _log(f"  (no UUID strings found in response)")
    except Exception:
        pass

    # Try protobuf parse
    try:
        fields = parse_fields(payload)
        _log(f"  Protobuf fields in response payload:")
        for fnum, vals in sorted(fields.items()):
            for v in vals:
                if isinstance(v, bytes):
                    try:
                        s = v.decode("utf-8", errors="replace")
                        _log(f"    field {fnum} (bytes, {len(v)}): {s[:80]!r}")
                    except Exception:
                        _log(f"    field {fnum} (bytes, {len(v)}): {v[:40].hex()}")
                else:
                    _log(f"    field {fnum} (int): {v}")
    except Exception as e:
        _log(f"  (protobuf parse error: {e})")


async def _relay(src_reader, dst_writer, tag: str):
    """Relay data from src to dst, logging everything."""
    try:
        while True:
            data = await asyncio.wait_for(src_reader.read(65536), timeout=60.0)
            if not data:
                break
            _log(f"[{tag}] {len(data)} bytes: {data.hex()}")
            dst_writer.write(data)
            await dst_writer.drain()
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionResetError):
        pass
    except Exception as e:
        _log(f"[{tag}] relay error: {e}")


async def handle_connection(reader, writer):
    peer = writer.get_extra_info("peername")
    _log(f"Game connected from {peer[0]}:{peer[1]}")

    real_reader = real_writer = None
    try:
        # Connect to real server
        real_reader, real_writer = await asyncio.wait_for(
            asyncio.open_connection(REAL_SERVER_IP, REAL_SERVER_PORT),
            timeout=10.0,
        )
        _log(f"Connected to real server {REAL_SERVER_IP}:{REAL_SERVER_PORT}")

        # Read game's first full packet (length-prefixed)
        hdr  = await asyncio.wait_for(reader.readexactly(4), timeout=10.0)
        plen = struct.unpack(">I", hdr)[0]
        body = await asyncio.wait_for(reader.readexactly(plen - 4), timeout=10.0)
        game_pkt = hdr + body

        _log(f"Game packet: {len(game_pkt)} bytes")
        _log(f"Game hex: {game_pkt[:64].hex()}…")

        # Extract JWT
        jwt = _try_extract_jwt(game_pkt)
        if jwt:
            exp, uid, remaining = _decode_jwt_expiry(jwt)
            _log(f"✓ JWT extracted! uid={uid} expires_in={remaining}")
            _log(f"  JWT: {jwt[:100]}…")
            _save_jwt(jwt, uid)
            _log(f"✓ JWT saved to config.json (_jwt_auth.jwt)")
        else:
            _log("✗ No JWT found — packet structure may differ")
            _log(f"  Raw (first 128): {game_pkt[:128].hex()}")

        # Forward game packet to real server
        real_writer.write(game_pkt)
        await real_writer.drain()

        # Read server's response (first packet)
        resp_hdr  = await asyncio.wait_for(real_reader.readexactly(4), timeout=15.0)
        resp_plen = struct.unpack(">I", resp_hdr)[0]
        resp_body = await asyncio.wait_for(real_reader.readexactly(resp_plen - 4), timeout=10.0)
        resp_pkt  = resp_hdr + resp_body

        _log("─" * 60)
        _log("SERVER RESPONSE (port 5003):")
        _analyze_response(resp_pkt)
        _log("─" * 60)

        # Forward response to game so it can continue normally
        writer.write(resp_pkt)
        await writer.drain()

        # Relay remaining traffic both ways
        await asyncio.gather(
            _relay(reader,      real_writer, "C→S"),
            _relay(real_reader, writer,      "S→C"),
        )

    except asyncio.TimeoutError:
        _log("Timeout waiting for data")
    except asyncio.IncompleteReadError:
        _log("Connection closed by peer")
    except Exception as e:
        _log(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        for w in (writer, real_writer):
            if w:
                try:
                    w.close()
                    await w.wait_closed()
                except Exception:
                    pass
        _log("Connection closed\n")


async def main():
    global _log_file
    _log_file = open(LOG_PATH, "w", encoding="utf-8")

    try:
        server = await asyncio.start_server(handle_connection, PROXY_HOST, PROXY_PORT)
    except OSError as e:
        print(f"ERROR: Cannot bind to port {PROXY_PORT}: {e}")
        sys.exit(1)

    print("=" * 60)
    print("  BPTimer Token Proxy (relay mode)")
    print("=" * 60)
    print(f"  Port {PROXY_PORT} → forwarding to {REAL_SERVER_IP}:{REAL_SERVER_PORT}")
    print()
    print("  Hosts file must have:")
    print("  127.0.0.1 bpm-sea-gamesvr.haoplay.net")
    print()
    print(f"  Full log → {LOG_PATH}")
    print()
    print("  Launch the game and log in normally.")
    print("  Game should work as usual — proxy is transparent.")
    print("  JWT will be extracted and saved automatically.")
    print("=" * 60)
    print()

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopped.")
        if _log_file:
            _log_file.close()
