"""
BPTimer Boarlet Suite — entrypoint.

Usage:
  python main.py tcp              # Live dashboard (default)
  python main.py tcp --log        # Classic log output
  python main.py win32            # Win32 PostMessage mode
  python main.py add-bot          # Add a new bot profile interactively
"""

import asyncio
import base64
import json
import logging
import os
import shutil
import struct
import sys
import time

log = logging.getLogger(__name__)

CONFIG_PATH = "config.json"

HOSTS_FILE    = r"C:\Windows\System32\drivers\etc\hosts"
HOSTS_ENTRY   = "127.0.0.1 bpm-sea-gamesvr.haoplay.net"
HOSTS_DOMAIN  = "bpm-sea-gamesvr.haoplay.net"
REAL_AUTH_IP   = "172.65.161.68"
REAL_AUTH_PORT = 5003


def load_config(path: str = CONFIG_PATH) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_config(cfg: dict, path: str = CONFIG_PATH) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")


# ── TCP mode ──────────────────────────────────────────────────────────────────

async def run_tcp(cfg: dict, use_dashboard: bool = True, slot_filter: set[int] | None = None) -> None:
    from core.client import BotClient
    from core.status import BotStatus
    from core.dashboard import dashboard_loop
    from detection.api_client import BPTimerAPIClient
    from detection.engine import detection_loop
    from alerts.discord import discord_sender

    raw_queue     = asyncio.Queue(maxsize=256)
    discord_queue = asyncio.Queue(maxsize=256)

    api_client = BPTimerAPIClient(cfg["bptimer_api_url"])
    seen_set   = set()

    statuses = []
    bots = []
    for slot_cfg in cfg["bots"]:
        if slot_filter is not None and slot_cfg["slot"] not in slot_filter:
            continue
        status = BotStatus(
            slot=slot_cfg["slot"],
            spawn_name=slot_cfg.get("spawn_name", f"Bot{slot_cfg['slot']}"),
        )
        statuses.append(status)
        bots.append(
            BotClient(slot_cfg, cfg, raw_queue, seen_set,
                      api_client=api_client, status=status)
        )

    if not bots:
        log.error("[Main] No bots matched the --slot filter.")
        return

    tasks = [
        *[b.run() for b in bots],
        detection_loop(raw_queue, discord_queue, api_client),
        discord_sender(discord_queue, cfg["discord_webhook"]),
    ]

    if use_dashboard:
        root = logging.getLogger()
        for h in root.handlers[:]:
            root.removeHandler(h)
        fh = logging.FileHandler("bot.log", encoding="utf-8")
        fh.setFormatter(logging.Formatter(
            "%(asctime)s  %(levelname)-8s  %(message)s", datefmt="%H:%M:%S"
        ))
        root.addHandler(fh)
        tasks.append(dashboard_loop(statuses, time.monotonic()))

    log.info(f"[Main] Starting {len(bots)} TCP bot(s)…")
    try:
        await asyncio.gather(*tasks)
    finally:
        await api_client.close()


# ── Win32 mode ────────────────────────────────────────────────────────────────

async def run_win32(cfg: dict) -> None:
    from win32_bot.controller import find_game_windows
    from win32_bot.actions import win32_scan_loop
    from detection.api_client import BPTimerAPIClient
    from detection.engine import detection_loop
    from alerts.discord import discord_sender

    raw_queue     = asyncio.Queue(maxsize=256)
    discord_queue = asyncio.Queue(maxsize=256)

    api_client = BPTimerAPIClient(cfg["bptimer_api_url"])

    windows = find_game_windows()
    if not windows:
        log.error("[Main] No Blue Protocol windows found. Launch the game first.")
        return

    bots_cfg = cfg["bots"]
    paired   = list(zip(windows, bots_cfg))

    log.info(f"[Main] Paired {len(paired)} window(s) to bot slot(s)")

    tasks = [
        *[
            win32_scan_loop(hwnd, slot_cfg, cfg, raw_queue)
            for hwnd, slot_cfg in paired
        ],
        detection_loop(raw_queue, discord_queue, api_client),
        discord_sender(discord_queue, cfg["discord_webhook"]),
    ]

    try:
        await asyncio.gather(*tasks)
    finally:
        await api_client.close()


# ── Add bot — capture proxy ───────────────────────────────────────────────────

def _check_hosts_file() -> bool:
    """Check if the hosts file has the redirect entry."""
    try:
        with open(HOSTS_FILE, "r") as f:
            content = f.read()
        # Check for the domain (ignore exact IP or comments)
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("#"):
                continue
            if HOSTS_DOMAIN in line:
                return True
    except PermissionError:
        pass
    except FileNotFoundError:
        pass
    return False


def _decode_jwt(jwt: str) -> dict:
    """Decode JWT payload, return dict with uid, exp, etc."""
    try:
        parts = jwt.split(".")
        padding = (4 - len(parts[1]) % 4) % 4
        decoded = base64.urlsafe_b64decode(parts[1] + "=" * padding)
        return json.loads(decoded)
    except Exception:
        return {}


def _extract_jwt_from_packet(raw: bytes) -> str | None:
    """Extract JWT from port-5003 first C→S ZRPC packet."""
    from proto.codec import parse_fields
    if len(raw) < 26:
        return None
    # Payload starts at offset 22 (ZRPC header), skip 4-byte inner method prefix
    payload = raw[22:]
    # The inner method prefix (4 bytes) will be parsed as junk fields,
    # but field 1 (the protobuf wrapper) should still be found
    try:
        outer = parse_fields(payload)
        inner_bytes = outer.get(1, [b""])[0]
        if not inner_bytes:
            # Try skipping the 4-byte inner method prefix explicitly
            outer = parse_fields(payload[4:])
            inner_bytes = outer.get(1, [b""])[0]
        if not inner_bytes:
            return None
        inner = parse_fields(inner_bytes)
        jwt_bytes = inner.get(3, [b""])[0]
        if not jwt_bytes:
            return None
        jwt = jwt_bytes.decode("ascii")
        if jwt.startswith("eyJ") and jwt.count(".") >= 2:
            return jwt
    except Exception:
        pass
    return None


def _extract_game_version(device_profile: bytes) -> str:
    """Extract game_version from device profile protobuf (field 9)."""
    from proto.codec import parse_fields, first_str
    try:
        # Skip 4-byte inner method prefix
        outer = parse_fields(device_profile[4:])
        inner_bytes = outer.get(1, [b""])[0]
        if inner_bytes:
            inner = parse_fields(inner_bytes)
            gv = first_str(inner, 9)
            if gv:
                return gv
    except Exception:
        pass
    return "1.0.35794.0"  # fallback


def _extract_client_resource_version(device_profile: bytes) -> str:
    """Extract client_resource_version from device profile protobuf (field 15)."""
    from proto.codec import parse_fields, first_str
    try:
        outer = parse_fields(device_profile[4:])
        inner_bytes = outer.get(1, [b""])[0]
        if inner_bytes:
            inner = parse_fields(inner_bytes)
            crv = first_str(inner, 15)
            if crv:
                return crv
    except Exception:
        pass
    return ""


async def _run_capture_proxy(captured: dict) -> None:
    """
    Run a transparent proxy on port 5003 to capture JWT + device profile.
    Waits for character select + world entry redirect before signaling done.
    Populates `captured` dict and keeps relaying until finalized.
    """

    async def _relay(src, dst):
        try:
            while True:
                data = await src.read(65536)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except Exception:
            pass

    async def _relay_detect_redirect(src, dst, cap):
        """Relay server → client, parsing ZRPC frames to detect NotifyEnterWorld redirect."""
        buf = b""
        found = False
        try:
            while True:
                data = await src.read(65536)
                if not data:
                    break
                dst.write(data)
                await dst.drain()

                if found:
                    continue

                buf += data
                while len(buf) >= 4:
                    plen = struct.unpack(">I", buf[:4])[0]
                    if plen > 1_000_000 or plen < 4:
                        buf = b""
                        break
                    if len(buf) < plen:
                        break
                    pkt = buf[:plen]
                    buf = buf[plen:]

                    if plen < 22:
                        continue
                    ptype = struct.unpack(">H", pkt[4:6])[0] & 0x7FFF
                    if ptype != 2:  # MSG_NOTIFY
                        continue
                    method = struct.unpack(">I", pkt[18:22])[0]
                    if method == 3:  # NotifyEnterWorld — redirect to scene server
                        found = True
                        # Try to extract scene server details from payload
                        try:
                            from core.gate_auth import _collect_all_strings
                            payload = pkt[22:]
                            strings = _collect_all_strings(payload)
                            host = port = None
                            for s in strings:
                                if "haoplay" in s or ("." in s and not s.startswith("0.") and not s.startswith("1.")):
                                    host = s
                                elif s.isdigit() and 1000 < int(s) < 65535:
                                    port = int(s)
                            if host:
                                cap["scene_host"] = host
                            if port:
                                cap["scene_port"] = port
                            print(f"  ✓ Character selected — redirect to {host or '?'}:{port or '?'}")
                        except Exception:
                            print(f"  ✓ Character selected — redirect detected!")
                        cap["done"] = True
        except Exception:
            pass

    async def handle_connection(reader, writer):
        peer = writer.get_extra_info("peername")
        print(f"\n  → Connection from game client ({peer[0]}:{peer[1]})")

        real_reader = real_writer = None
        try:
            real_reader, real_writer = await asyncio.wait_for(
                asyncio.open_connection(REAL_AUTH_IP, REAL_AUTH_PORT),
                timeout=10.0,
            )

            # Read game packets, skipping keepalives until we get the real login
            forwarded_keepalives = []
            game_pkt = None
            for _ in range(20):  # safety limit
                hdr = await asyncio.wait_for(reader.readexactly(4), timeout=15.0)
                plen = struct.unpack(">I", hdr)[0]
                body = await asyncio.wait_for(reader.readexactly(plen - 4), timeout=15.0)
                pkt = hdr + body

                if plen <= 6:
                    # Keepalive or heartbeat — forward to real server, keep reading
                    forwarded_keepalives.append(pkt)
                    print(f"  ... skipped keepalive ({plen}b)")
                    continue

                if plen < 26:
                    # Too short to be a login packet — forward and skip
                    forwarded_keepalives.append(pkt)
                    print(f"  ... skipped short packet ({plen}b)")
                    continue

                game_pkt = pkt
                break

            if game_pkt is None:
                print("  ✗ No login packet received (only keepalives)")
                captured["done"] = True
                captured["error"] = True
                return

            # Forward any keepalives that arrived before the login packet
            for ka in forwarded_keepalives:
                real_writer.write(ka)
            if forwarded_keepalives:
                await real_writer.drain()

            # Extract device profile (everything after 22-byte ZRPC header)
            device_profile = game_pkt[22:]

            # Extract JWT
            jwt = _extract_jwt_from_packet(game_pkt)
            if jwt:
                jwt_data = _decode_jwt(jwt)
                uid = str(jwt_data.get("uid", ""))
                exp = jwt_data.get("exp", 0)
                remaining = max(0, exp - int(time.time()))
                days = remaining // 86400
                hours = (remaining % 86400) // 3600

                game_version = _extract_game_version(device_profile)
                client_resource_version = _extract_client_resource_version(device_profile)

                captured["jwt"] = jwt
                captured["uid"] = uid
                captured["account_id"] = f"6_{uid}" if uid else ""
                captured["device_profile"] = device_profile
                captured["game_version"] = game_version
                captured["client_resource_version"] = client_resource_version
                captured["exp_str"] = f"{days}d {hours}h"

                print(f"  ✓ JWT captured (uid={uid}, expires in {days}d {hours}h)")
                print(f"  ✓ Device profile captured ({len(device_profile)} bytes)")
                print(f"  ✓ Account: {captured['account_id']}")
                print(f"  ✓ Game version: {game_version}")
                print(f"  ✓ Client resource version: {client_resource_version}")
            else:
                print("  ✗ Could not extract JWT from game packet")
                print(f"    Packet size: {len(game_pkt)} bytes")
                captured["done"] = True
                captured["error"] = True

            # Forward to real server
            real_writer.write(game_pkt)
            await real_writer.drain()

            if captured.get("error"):
                return

            # Tell user to remove hosts entry so scene server connection works
            print(f"\n  ┌──────────────────────────────────────────────────┐")
            print(f"  │  Remove the hosts entry NOW before selecting     │")
            print(f"  │  your character! The proxy connection stays       │")
            print(f"  │  alive — only new DNS lookups are affected.       │")
            print(f"  │                                                   │")
            print(f"  │  Remove: {HOSTS_ENTRY:<39s} │")
            print(f"  │  From:   {HOSTS_FILE:<39s} │")
            print(f"  └──────────────────────────────────────────────────┘")
            print(f"\n  After removing, select your character and enter the world.")
            print(f"  Waiting for world entry redirect…")
            await asyncio.gather(
                _relay(reader, real_writer),
                _relay_detect_redirect(real_reader, writer, captured),
            )

            # If connection closed before redirect (e.g. user quit game), fall back
            if not captured.get("done"):
                if captured.get("jwt"):
                    print(f"\n  ⚠ Connection closed before world entry.")
                    print(f"  Using gate-level capture data (JWT + device profile).")
                    captured["done"] = True
                else:
                    captured["done"] = True
                    captured["error"] = True
        except Exception as e:
            print(f"  ✗ Proxy error: {e}")
            captured["done"] = True
            captured["error"] = True
        finally:
            for w in (writer, real_writer):
                if w:
                    try:
                        w.close()
                    except Exception:
                        pass

    active_tasks: list[asyncio.Task] = []

    async def _tracked_handle(reader, writer):
        task = asyncio.current_task()
        active_tasks.append(task)
        try:
            await handle_connection(reader, writer)
        finally:
            active_tasks.remove(task)

    try:
        server = await asyncio.start_server(_tracked_handle, "0.0.0.0", REAL_AUTH_PORT)
    except OSError as e:
        print(f"\n  ✗ Cannot bind to port {REAL_AUTH_PORT}: {e}")
        print(f"    Make sure no other process is using port {REAL_AUTH_PORT}")
        captured["done"] = True
        captured["error"] = True
        return

    print(f"  Proxy listening on port {REAL_AUTH_PORT}…")
    print(f"  Launch Blue Protocol, log in, select character, and enter the game.")
    print(f"  Waiting for connection…")

    async with server:
        # Wait until capture is done, then keep serving for relay
        while not captured.get("done"):
            await asyncio.sleep(0.3)

        # Keep relay alive until user presses Enter (handled by caller)
        try:
            while not captured.get("finalize"):
                await asyncio.sleep(0.3)
        except asyncio.CancelledError:
            pass

    # Cancel any lingering connection handler tasks (relay loops)
    for t in list(active_tasks):
        t.cancel()
    if active_tasks:
        await asyncio.gather(*active_tasks, return_exceptions=True)

    server.close()


def add_bot_interactive() -> None:
    cfg = load_config()
    bots = cfg.get("bots", [])
    existing_slots = {b["slot"] for b in bots}
    new_slot = 0
    while new_slot in existing_slots:
        new_slot += 1

    print(f"\n  ══════════════════════════════════════════")
    print(f"  Add Bot — Slot #{new_slot}")
    print(f"  ══════════════════════════════════════════")

    # Spawn name
    spawn_name = input("\n  Spawn location (e.g. Cliff Ruins): ").strip()
    if not spawn_name:
        spawn_name = f"Location{new_slot}"

    # Account choice
    has_existing = len(bots) > 0
    if has_existing:
        print(f"\n  Account setup:")
        print(f"  [1] Same account as Bot #0 (share JWT + device profile)")
        print(f"  [2] New account — auto-capture via login proxy")
        choice = input(f"  Choice [1]: ").strip() or "1"
    else:
        choice = "2"

    trace_dir = "data/packet_traces"
    os.makedirs(trace_dir, exist_ok=True)
    new_trace = f"{trace_dir}/slot_{new_slot}.json"
    new_bot: dict = {"slot": new_slot, "spawn_name": spawn_name}

    if choice == "2":
        # ── Capture mode ──────────────────────────────────────────
        _run_capture_flow(cfg, bots, new_slot, new_bot, new_trace, spawn_name)
    else:
        # ── Reuse existing account ────────────────────────────────
        _add_same_account(cfg, bots, new_slot, new_bot, new_trace, spawn_name)


def _run_capture_flow(cfg, bots, new_slot, new_bot, new_trace, spawn_name):
    print(f"\n  ──── New Account Capture ────")

    # Step 1: Check hosts file
    print(f"\n  Step 1: Hosts file")
    if _check_hosts_file():
        print(f"  ✓ Entry found: {HOSTS_ENTRY}")
    else:
        print(f"  ⚠ Hosts file needs this entry (required for proxy):")
        print(f"    {HOSTS_ENTRY}")
        print(f"    File: {HOSTS_FILE}")
        print(f"    → Open Notepad as Administrator, add the line, save.")
        input(f"\n  Press Enter when done…")

        if not _check_hosts_file():
            print(f"  ⚠ Entry still not found — continuing anyway (proxy may not work)")

    # Step 2: Run capture proxy
    print(f"\n  Step 2: Capture proxy")

    captured: dict = {}

    # Run proxy in a background thread so we can wait for Enter in the main thread
    import threading

    loop = asyncio.new_event_loop()
    proxy_thread = threading.Thread(
        target=lambda: loop.run_until_complete(_run_capture_proxy(captured)),
        daemon=True,
    )
    proxy_thread.start()

    # Wait for capture to complete
    while not captured.get("done"):
        time.sleep(0.3)

    if captured.get("error"):
        print(f"\n  Capture failed. Please try again.")
        print(f"  Make sure:")
        print(f"    - Hosts file entry is correct")
        print(f"    - Game is not already running")
        print(f"    - No other process on port {REAL_AUTH_PORT}")
        captured["finalize"] = True
        return

    input(f"\n  Press Enter to save bot profile and finish…")
    captured["finalize"] = True

    # Save device profile
    dp_path = f"device_profile_slot{new_slot}.bin"
    with open(dp_path, "wb") as f:
        f.write(captured["device_profile"])

    # Save trace file — extract client_resource_version from device profile
    client_res_ver = captured.get("client_resource_version", "")
    if not client_res_ver:
        # Fallback: try existing slot_0
        if os.path.exists(f"data/packet_traces/slot_0.json"):
            try:
                with open(f"data/packet_traces/slot_0.json") as f:
                    t = json.load(f)
                client_res_ver = t.get("client_resource_version", "")
            except Exception:
                pass

    trace_data = {
        "account_id": captured["account_id"],
        "client_resource_version": client_res_ver,
        "game_version": captured.get("game_version", "1.0.37620.0"),
        "os_enum": 5,
    }
    with open(new_trace, "w") as f:
        json.dump(trace_data, f, indent=2)

    # Build bot config entry
    new_bot["trace_file"] = new_trace
    new_bot["device_profile"] = dp_path
    new_bot["_jwt_auth"] = {
        "jwt": captured["jwt"],
        "captured_at": int(time.time()),
        "uid": captured["uid"],
    }

    bots = cfg.get("bots", [])
    bots.append(new_bot)
    cfg["bots"] = bots
    save_config(cfg)

    print(f"\n  ══════════════════════════════════════════")
    print(f"  ✓ Bot #{new_slot} saved to {CONFIG_PATH}")
    print(f"  ──────────────────────────────────────────")
    print(f"    Spawn:          {spawn_name}")
    print(f"    Account:        {captured['account_id']}")
    print(f"    Device profile: {dp_path}")
    print(f"    Trace:          {new_trace}")
    print(f"    JWT:            per-bot ({captured.get('exp_str', '?')} remaining)")
    print(f"  ══════════════════════════════════════════")
    print()
    print(f"  ⚠ Remember to remove the hosts entry when done:")
    print(f"    Remove: {HOSTS_ENTRY}")
    print(f"    From:   {HOSTS_FILE}")
    print()
    print(f"  Run 'python main.py tcp' to start all bots.")
    print()


def _add_same_account(cfg, bots, new_slot, new_bot, new_trace, spawn_name):
    """Add a bot that shares JWT + device profile with an existing bot."""
    # Copy trace from slot 0
    src_trace = bots[0].get("trace_file", "data/packet_traces/slot_0.json") if bots else None
    if src_trace and os.path.exists(src_trace):
        shutil.copy2(src_trace, new_trace)
    else:
        with open(new_trace, "w") as f:
            json.dump({
                "account_id": "FILL_ME",
                "client_resource_version": "0.0.32499.35794",
                "game_version": "1.0.35794.0",
                "os_enum": 5,
            }, f, indent=2)

    new_bot["trace_file"] = new_trace
    # Uses global JWT + global device_profile.bin (no per-bot override needed)

    bots_list = cfg.get("bots", [])
    bots_list.append(new_bot)
    cfg["bots"] = bots_list
    save_config(cfg)

    print(f"\n  ══════════════════════════════════════════")
    print(f"  ✓ Bot #{new_slot} saved to {CONFIG_PATH}")
    print(f"  ──────────────────────────────────────────")
    print(f"    Spawn:   {spawn_name}")
    print(f"    Account: shared with Bot #0")
    print(f"    JWT:     shared (global)")
    print(f"    Trace:   {new_trace}")
    print(f"  ══════════════════════════════════════════")
    print()
    print(f"  Run 'python main.py tcp' to start all bots.")
    print()


# ── Refresh — recapture JWT + device profile for existing bots ────────────────

def refresh_bots() -> None:
    """
    Refresh JWT + device profile for all existing bots.

    Groups bots by account (uid) to minimize the number of logins needed.
    For each unique account, runs the capture proxy once, then updates
    all bots sharing that account.

    Usage:
      python main.py refresh              # All bots
      python main.py refresh --slot 0     # Only bot #0
      python main.py refresh --slot 0 2 5 # Only bots #0, #2, #5
    """
    cfg = load_config()
    bots = cfg.get("bots", [])
    if not bots:
        print("\n  No bots configured. Run 'python main.py add-bot' first.")
        return

    # Parse --slot filter (supports multiple: --slot 0 2 5)
    slot_filter = _parse_slot_args()

    # Filter bots if --slot specified
    if slot_filter is not None:
        target_bots = [b for b in bots if b["slot"] in slot_filter]
        if not target_bots:
            print(f"\n  No bots found for slots {sorted(slot_filter)}.")
            return
    else:
        target_bots = bots

    # Group bots by uid (account)
    uid_groups: dict[str, list[dict]] = {}
    for bot in target_bots:
        uid = bot.get("_jwt_auth", {}).get("uid", "unknown")
        uid_groups.setdefault(uid, []).append(bot)

    total_bots = len(target_bots)
    total_accounts = len(uid_groups)

    print(f"\n  ══════════════════════════════════════════")
    print(f"  Refresh Captures — {total_bots} bot(s), {total_accounts} unique account(s)")
    print(f"  ══════════════════════════════════════════")

    # Show current status of each account
    for uid, group in uid_groups.items():
        slots = [str(b["slot"]) for b in group]
        # Check JWT expiry
        jwt = group[0].get("_jwt_auth", {}).get("jwt", "")
        exp_str = "unknown"
        if jwt:
            jwt_data = _decode_jwt(jwt)
            exp = jwt_data.get("exp", 0)
            if exp:
                remaining = exp - int(time.time())
                if remaining <= 0:
                    exp_str = "EXPIRED"
                else:
                    days = remaining // 86400
                    hours = (remaining % 86400) // 3600
                    exp_str = f"{days}d {hours}h remaining"
        print(f"\n  Account uid={uid}")
        print(f"    Slots: {', '.join(slots)}")
        print(f"    JWT:   {exp_str}")

    # Check hosts file
    print(f"\n  ──── Step 1: Hosts file ────")
    if _check_hosts_file():
        print(f"  OK: {HOSTS_ENTRY}")
    else:
        print(f"  Hosts file needs this entry:")
        print(f"    {HOSTS_ENTRY}")
        print(f"    File: {HOSTS_FILE}")
        print(f"    Open Notepad as Administrator, add the line, save.")
        input(f"\n  Press Enter when done...")

        if not _check_hosts_file():
            print(f"  Entry still not found — continuing anyway")

    # Capture each account
    print(f"\n  ──── Step 2: Capture ({total_accounts} account(s)) ────")
    print(f"  You will log in once per account.")
    print(f"  After each login, the proxy captures the fresh JWT + device profile.")

    import threading

    account_num = 0
    for uid, group in uid_groups.items():
        account_num += 1
        slots = [str(b["slot"]) for b in group]
        spawn_names = [b.get("spawn_name", f"Bot#{b['slot']}") for b in group]

        print(f"\n  ════ Account {account_num}/{total_accounts} (uid={uid}) ════")
        print(f"  Bots:  {', '.join(f'#{s} ({n})' for s, n in zip(slots, spawn_names))}")
        input(f"  Press Enter to start proxy, then log in with this account...")

        captured: dict = {}

        loop = asyncio.new_event_loop()
        proxy_thread = threading.Thread(
            target=lambda: loop.run_until_complete(_run_capture_proxy(captured)),
            daemon=True,
        )
        proxy_thread.start()

        # Wait for capture
        while not captured.get("done"):
            time.sleep(0.3)

        if captured.get("error"):
            print(f"\n  Capture FAILED for uid={uid}. Skipping these bots.")
            print(f"  Make sure:")
            print(f"    - Hosts file entry is correct")
            print(f"    - Game is not already running")
            print(f"    - No other process on port {REAL_AUTH_PORT}")
            captured["finalize"] = True
            continue

        input(f"\n  Capture OK! Press Enter to save and continue...")
        captured["finalize"] = True

        # Give the proxy thread a moment to shut down
        time.sleep(0.5)

        # Get new versions
        new_game_version = captured.get("game_version", "")
        new_client_resource_version = captured.get("client_resource_version", "")

        # Update all bots in this group
        for bot in group:
            slot = bot["slot"]

            # Update device profile file
            dp_path = bot.get("device_profile", f"device_profile_slot{slot}.bin")
            with open(dp_path, "wb") as f:
                f.write(captured["device_profile"])
            print(f"    Slot #{slot}: device profile -> {dp_path} ({len(captured['device_profile'])}b)")

            # Update JWT in config
            bot["_jwt_auth"] = {
                "jwt": captured["jwt"],
                "captured_at": int(time.time()),
                "uid": captured.get("uid", uid),
            }
            print(f"    Slot #{slot}: JWT updated (expires {captured.get('exp_str', '?')})")

            # Update account_id + game_version + client_resource_version in trace file
            trace_file = bot.get("trace_file", f"data/packet_traces/slot_{slot}.json")
            new_account_id = captured.get("account_id", "")
            if os.path.exists(trace_file):
                try:
                    with open(trace_file, "r") as f:
                        trace = json.load(f)
                    changes = []
                    if new_account_id:
                        old = trace.get("account_id", "")
                        trace["account_id"] = new_account_id
                        if old != new_account_id:
                            changes.append(f"account_id {old} -> {new_account_id}")
                    if new_game_version:
                        old = trace.get("game_version", "")
                        trace["game_version"] = new_game_version
                        if old != new_game_version:
                            changes.append(f"game_version {old} -> {new_game_version}")
                    if new_client_resource_version:
                        old = trace.get("client_resource_version", "")
                        trace["client_resource_version"] = new_client_resource_version
                        if old != new_client_resource_version:
                            changes.append(f"client_resource_version {old} -> {new_client_resource_version}")
                    with open(trace_file, "w") as f:
                        json.dump(trace, f, indent=2)
                    if changes:
                        for c in changes:
                            print(f"    Slot #{slot}: {c}")
                    else:
                        print(f"    Slot #{slot}: trace unchanged")
                except Exception as e:
                    print(f"    Slot #{slot}: trace update failed: {e}")

    # Save config
    save_config(cfg)

    print(f"\n  ══════════════════════════════════════════")
    print(f"  Refresh complete! Updated {total_bots} bot(s).")
    print(f"  ══════════════════════════════════════════")
    print()
    print(f"  Remember to remove hosts entry when done:")
    print(f"    Remove: {HOSTS_ENTRY}")
    print(f"    From:   {HOSTS_FILE}")
    print()
    print(f"  Run 'python main.py tcp' to start all bots.")
    print()


# ── Entry ─────────────────────────────────────────────────────────────────────

def _parse_slot_args() -> set[int] | None:
    """Parse --slot N [N ...] from sys.argv. Returns None if not specified."""
    if "--slot" not in sys.argv:
        return None
    idx = sys.argv.index("--slot")
    slots = set()
    for arg in sys.argv[idx + 1:]:
        if arg.startswith("-"):
            break
        try:
            slots.add(int(arg))
        except ValueError:
            break
    if not slots:
        print("  Error: --slot requires at least one slot number")
        sys.exit(1)
    return slots


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in ("tcp", "win32", "add-bot", "refresh"):
        print("Usage:")
        print("  python main.py tcp                  # All bots, live dashboard")
        print("  python main.py tcp --log            # All bots, classic log output")
        print("  python main.py tcp --slot 1         # Run only bot #1")
        print("  python main.py tcp --slot 1 3 5     # Run bots #1, #3, #5")
        print("  python main.py tcp --slot 1 --log   # Single bot, log output")
        print("  python main.py win32                # Win32 game window control")
        print("  python main.py add-bot              # Add a new bot profile")
        print("  python main.py refresh              # Refresh JWT + device profile for all bots")
        print("  python main.py refresh --slot 0     # Refresh only bot #0")
        print("  python main.py refresh --slot 0 2 5 # Refresh bots #0, #2, #5")
        print("  python main.py refresh --slot 3     # Refresh only bot #3")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "add-bot":
        add_bot_interactive()
        return

    if mode == "refresh":
        refresh_bots()
        return

    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )

    cfg = load_config()
    log.info(f"[Main] Mode: {mode.upper()}")

    if mode == "tcp":
        use_dashboard = "--log" not in sys.argv
        slot_filter = _parse_slot_args()
        if slot_filter:
            log.info(f"[Main] Slot filter: {sorted(slot_filter)}")
        if use_dashboard:
            # Enable ANSI on Windows and UTF-8 output
            if sys.platform == "win32":
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                sys.stdout.reconfigure(encoding="utf-8")
            log.info(f"[Main] Starting dashboard mode (use --log for classic output)")
        try:
            asyncio.run(run_tcp(cfg, use_dashboard=use_dashboard, slot_filter=slot_filter))
        except KeyboardInterrupt:
            if use_dashboard:
                sys.stdout.write("\033[?25h\n")
                sys.stdout.flush()
            print("\nStopped.")
    else:
        asyncio.run(run_win32(cfg))


if __name__ == "__main__":
    main()
