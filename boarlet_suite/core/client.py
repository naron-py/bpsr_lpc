"""
BotClient — one asyncio coroutine per bot slot.

Lifecycle:
  DISCONNECTED → CONNECTED → AUTHENTICATING → IN_WORLD → (REDIRECTING →) IN_WORLD → …

Each client independently cycles all configured World Lines.
On redirect (MethodId 3), it closes the gate socket and opens a new connection
to the scene server, logging in with the handover token instead of the JWT.
"""

import asyncio
import logging
import time

from core import login, scanner, gate_auth
from core.redirect import open_scene_connection
from core.scanner import ServerDisconnected, SwitchResult
from core.status import BotStatus
from detection.api_client import BPTimerAPIClient

log = logging.getLogger(__name__)

RECONNECT_DELAY = 5.0   # seconds to wait before retrying after a crash
DEAD_LINE_REFRESH_SEC = 60.0  # how often to refresh dead-line list from API


class BotClient:
    def __init__(
        self,
        slot_cfg:    dict,
        global_cfg:  dict,
        alert_queue: asyncio.Queue,
        seen_set:    set,
        api_client:  BPTimerAPIClient | None = None,
        status:      BotStatus | None = None,
    ):
        self.slot_cfg    = slot_cfg
        self.global_cfg  = global_cfg
        self.alert_queue = alert_queue
        self.seen_set    = seen_set
        self.slot_id     = slot_cfg["slot"]
        self.api_client  = api_client
        self.status      = status or BotStatus(slot=self.slot_id, spawn_name=slot_cfg.get("spawn_name", ""))
        self._dead_lines: set[int] = set()
        self._dead_lines_ts: float = 0.0
        self._resume_index: int = 0

    # ── Public entry point ────────────────────────────────────────────────────

    async def run(self) -> None:
        """Outer reconnect loop — restarts automatically on any failure."""
        while True:
            try:
                await self._session()
            except Exception as e:
                self.status.state = "Reconnecting"
                self.status.error = str(e)[:80]
                self.status.event(f"crashed: {e!r}")
                log.warning(
                    f"[Bot{self.slot_id}] Crashed: {e!r}. "
                    f"Reconnecting in {RECONNECT_DELAY}s…"
                )
                await asyncio.sleep(RECONNECT_DELAY)

    async def _refresh_dead_lines(self) -> None:
        """Refresh dead-line set from BPTimer API if stale."""
        now = time.monotonic()
        if now - self._dead_lines_ts < DEAD_LINE_REFRESH_SEC:
            return
        if self.api_client is None:
            return
        try:
            new_dead = await self.api_client.get_dead_lines()
            self._dead_lines_ts = now
            if new_dead != self._dead_lines:
                self._dead_lines = new_dead
                alive_count = len(self.global_cfg["lines"]) - len(self._dead_lines)
                self.status.total_alive = alive_count
                self.status.total_dead = len(self._dead_lines)
                self.status.event(f"dead lines: {len(self._dead_lines)} dead, {alive_count} alive")
                log.info(
                    f"[Bot{self.slot_id}] Dead lines updated: "
                    f"{len(self._dead_lines)} dead, {alive_count} alive to scan"
                )
        except Exception as e:
            log.warning(f"[Bot{self.slot_id}] Dead-line refresh failed: {e}")

    # ── Session (one gate connection) ─────────────────────────────────────────

    async def _session(self) -> None:
        auth_ip    = self.global_cfg.get("auth_ip", "172.65.161.68")
        lines      = self.global_cfg["lines"]
        boarlet_id = self.global_cfg["loyal_boarlet_id"]
        scene_id   = self.global_cfg.get("scene_id", 13)

        # ── Step 1: Authenticate ──────────────────────────────────────
        self.status.state = "Authenticating"
        self.status.error = ""

        jwt = gate_auth.load_jwt(self.global_cfg, self.slot_cfg)
        device_profile = self.slot_cfg.get("device_profile", "device_profile.bin")
        session_blob, char_id, reader, writer = await gate_auth.get_session_token(
            auth_ip, jwt, device_profile=device_profile
        )

        log.info(f"[Bot{self.slot_id}] Continuing proxy handshake on {auth_ip}:5003")
        keepalive_task = asyncio.create_task(self._keepalive_loop(writer))

        try:
            self.status.state = "Logging in"
            gate_result = await login.do_proxy_login(
                writer, reader,
                self.slot_cfg, session_blob, char_id
            )
            gate_session = gate_result["session_token"]
            target = f"{gate_result['target_host']}:{gate_result['target_port']}"
            self.status.server = target
            self.status.event(f"login → {target}")
            log.info(f"[Bot{self.slot_id}] Gate login OK. Target -> {target}")

            keepalive_task.cancel()
            writer.close()
            await writer.wait_closed()

            from core.redirect import RedirectInfo
            redirect = RedirectInfo(
                ip=gate_result["target_host"],
                port=gate_result["target_port"],
                token="",
                line_id=lines[0]
            )
            reader, writer = await open_scene_connection(redirect)
            keepalive_task = asyncio.create_task(self._keepalive_loop(writer))
            scene_result = await login.do_scene_login(
                writer, reader, self.slot_cfg,
                token_override=gate_result["handover_token"],
                gate_session_token=gate_session,
                ack_server_sequence=30,
                scene_id=scene_id,
                is_relogin=False,
                char_id=char_id,
            )
            self.status.state = "Scanning"
            current_line = scene_result.get("current_line_id", 0)
            scene_guid = scene_result.get("scene_guid", "")
            self.status.event(f"scene login OK (line={current_line}), scanning…")
            log.info(
                f"[Bot{self.slot_id}] Scene login OK. "
                f"Current line={current_line}, scene_guid={scene_guid[:16] or '(none)'}…"
            )

            # Process buffered FrameDown packets from login (initial entity dump)
            from core.zrpc import decode_packet, MSG_FRAME_DOWN
            buffered = scene_result.get("buffered_packets", [])
            if buffered:
                log.info(f"[Bot{self.slot_id}] Processing {len(buffered)} buffered FrameDown from login")
                for raw_pkt in buffered:
                    try:
                        pkt = decode_packet(raw_pkt)
                        if pkt["msg_type"] == MSG_FRAME_DOWN:
                            scanner._handle_frame_down_raw(
                                pkt["payload"], boarlet_id,
                                self.alert_queue, self.slot_cfg,
                                line_id=lines[0],
                            )
                    except Exception as e:
                        log.debug(f"[Bot{self.slot_id}] Buffered packet error: {e}")

            # Track the current login token — updates on each re-login
            current_token = gate_result["handover_token"]
            current_session = gate_session

            # ── Step 2: Scan loop ───────────────────────────────────
            # The scanner now handles the full state machine for same-server
            # redirects: switch → redirect → ConnectWorld → setup → scan.
            # We only handle different-server redirects here (new socket).
            line_idx = self._resume_index
            cycle_start_scans = self.status.lines_scanned
            while True:
                line_id = lines[line_idx % len(lines)]

                # Detect full cycle
                if line_idx > 0 and line_idx % len(lines) == 0:
                    self.status.cycle_count += 1
                    scans_this_cycle = self.status.lines_scanned - cycle_start_scans
                    self.status.event(
                        f"cycle #{self.status.cycle_count} done "
                        f"({scans_this_cycle} lines, {self.status.alerts_found} alerts)"
                    )
                    cycle_start_scans = self.status.lines_scanned

                line_idx += 1

                # Refresh dead-line list and skip dead lines
                await self._refresh_dead_lines()
                if line_id in self._dead_lines:
                    continue

                self.status.current_line = line_id
                log.info(f"[Bot{self.slot_id}] Scanning line {line_id}…")

                try:
                    q_before = self.alert_queue.qsize()
                    self.status.state = "Switching"
                    switch_result: SwitchResult = await scanner.switch_and_scan(
                        reader, writer, line_id, boarlet_id,
                        self.alert_queue, self.slot_cfg,
                        scene_id=scene_id,
                        current_token=current_token,
                        gate_session_token=current_session,
                    )
                    # Track alerts
                    new_alerts = self.alert_queue.qsize() - q_before
                    if new_alerts > 0:
                        self.status.alerts_found += new_alerts
                        self.status.event(f"BOARLET FOUND on line {line_id}!")
                except ServerDisconnected as e:
                    log.warning(f"[Bot{self.slot_id}] {e} — will reconnect and resume")
                    self._resume_index = (line_idx - 1) % len(lines)
                    raise

                self.status.lines_scanned += 1

                # ── Update auth state from scanner result ──
                if switch_result.reauth_done:
                    # Same-server redirect was handled inline by the scanner.
                    if switch_result.new_token:
                        current_token = switch_result.new_token
                    if switch_result.new_session:
                        current_session = switch_result.new_session
                    self.status.state = "Scanning"
                    log.info(f"[Bot{self.slot_id}] Re-auth OK on line {line_id} (handled by scanner)")

                elif switch_result.needs_reconnect and switch_result.redirect:
                    # ── Different-server redirect: open new connection ──
                    redirect = switch_result.redirect
                    keepalive_task.cancel()
                    writer.close()
                    await writer.wait_closed()

                    self.status.state = "Redirecting"
                    target = f"{redirect.ip}:{redirect.port}"
                    self.status.server = target
                    self.status.event(f"redirect → {target}")
                    log.info(f"[Bot{self.slot_id}] Different-server redirect → {target}")

                    reader, writer = await open_scene_connection(redirect)
                    keepalive_task = asyncio.create_task(self._keepalive_loop(writer))
                    relogin_token = redirect.token or current_token

                    redir_result = await login.do_scene_login(
                        writer, reader, self.slot_cfg,
                        token_override=relogin_token,
                        gate_session_token=current_session,
                        ack_server_sequence=30,
                        scene_id=scene_id,
                        is_relogin=True,
                    )

                    if redir_result.get("session_token"):
                        current_session = redir_result["session_token"]
                    current_token = relogin_token

                    self.status.state = "Scanning"
                    log.info(f"[Bot{self.slot_id}] Re-login OK after server redirect on line {line_id}")

                    # Process buffered FrameDown from redirect login
                    for raw_pkt in redir_result.get("buffered_packets", []):
                        try:
                            pkt = decode_packet(raw_pkt)
                            if pkt["msg_type"] == MSG_FRAME_DOWN:
                                scanner._handle_frame_down_raw(
                                    pkt["payload"], boarlet_id,
                                    self.alert_queue, self.slot_cfg,
                                    line_id=line_id,
                                )
                        except Exception:
                            pass
                else:
                    self.status.state = "Scanning"

        finally:
            try:
                keepalive_task.cancel()
            except Exception:
                pass
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _keepalive_loop(self, writer) -> None:
        """Send 6-byte heartbeat every 5 seconds to keep the socket alive."""
        while True:
            await asyncio.sleep(5.0)
            try:
                writer.write(b'\x00\x00\x00\x06\x00\x04')
                await writer.drain()
            except Exception:
                break
