"""
Live terminal dashboard for BPTimer Boarlet Suite.

Renders a compact status view using ANSI escape codes.
Refreshes every 0.5 seconds.
"""

import asyncio
import sys
import time

from core.status import BotStatus

# ── ANSI escape codes ────────────────────────────────────────────────────────
RST   = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
GREEN = "\033[32m"
YELLO = "\033[33m"
RED   = "\033[31m"
CYAN  = "\033[36m"
WHITE = "\033[97m"
BGDIM = "\033[48;5;236m"  # subtle dark background for header

STATE_STYLE = {
    "Starting":       (DIM,   "○"),
    "Authenticating": (YELLO, "◌"),
    "Logging in":     (YELLO, "◌"),
    "Scanning":       (GREEN, "●"),
    "Redirecting":    (CYAN,  "↻"),
    "Reconnecting":   (YELLO, "↺"),
    "Error":          (RED,   "✗"),
}


def _uptime(seconds: float) -> str:
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m{s % 60:02d}s"
    h, r = divmod(s, 3600)
    return f"{h}h{r // 60:02d}m"


def _render(statuses: list[BotStatus], start_time: float) -> str:
    lines: list[str] = []
    now = time.strftime("%H:%M:%S")
    up = _uptime(time.monotonic() - start_time)

    # Header
    lines.append(f"  {BOLD}{CYAN}BPTimer Boarlet Suite{RST}  {DIM}TCP Scanner{RST}    {DIM}{now}  up {up}{RST}")
    lines.append(f"  {DIM}{'─' * 62}{RST}")

    # Column header
    lines.append(
        f"  {DIM}{'Bot':<5}{'State':<18}{'Line':<8}{'Location':<18}{'Scans':<8}{'Cycle':<6}{RST}"
    )

    # Bot rows
    for st in statuses:
        color, icon = STATE_STYLE.get(st.state, (DIM, "?"))
        state_str = f"{icon} {st.state}"

        if st.current_line > 0:
            line_str = f"L{st.current_line}"
        else:
            line_str = "—"

        scans = str(st.lines_scanned)
        cycle = f"#{st.cycle_count}" if st.cycle_count > 0 else "—"

        lines.append(
            f"  {BOLD}#{st.slot:<4}{RST}"
            f"{color}{state_str:<18}{RST}"
            f"{WHITE}{line_str:<8}{RST}"
            f"{st.spawn_name:<18}"
            f"{scans:<8}"
            f"{cycle:<6}"
        )

        if st.state == "Error" and st.error:
            lines.append(f"        {RED}{DIM}{st.error[:55]}{RST}")

    lines.append(f"  {DIM}{'─' * 62}{RST}")

    # Summary
    total_alive = statuses[0].total_alive if statuses else 0
    total_dead = statuses[0].total_dead if statuses else 0
    total_alerts = sum(s.alerts_found for s in statuses)

    alert_color = GREEN if total_alerts == 0 else f"{BOLD}{YELLO}"
    lines.append(
        f"  Lines: {GREEN}{total_alive} alive{RST} / {RED}{total_dead} dead{RST} / 70 total"
        f"    Alerts: {alert_color}{total_alerts}{RST}"
    )

    lines.append(f"  {DIM}{'─' * 62}{RST}")

    # Recent events (collect from all bots, sort by time, show last 8)
    all_events = []
    for st in statuses:
        all_events.extend(st.events)
    # Events are already timestamped strings — sort lexically (HH:MM:SS prefix)
    all_events.sort()
    recent = all_events[-8:]

    if recent:
        lines.append(f"  {DIM}Events:{RST}")
        for ev in recent:
            lines.append(f"  {DIM}{ev}{RST}")
    else:
        lines.append(f"  {DIM}Waiting for events…{RST}")

    # Pad to fixed height to prevent terminal jumping
    while len(lines) < 24:
        lines.append("")

    return lines


async def dashboard_loop(statuses: list[BotStatus], start_time: float) -> None:
    """
    Render the dashboard in a loop. Runs as a background task.
    """
    # Clear screen and hide cursor
    sys.stdout.write("\033[2J\033[H\033[?25l")
    sys.stdout.flush()

    try:
        while True:
            rendered = _render(statuses, start_time)
            # Move cursor to home and draw
            buf = ["\033[H"]
            for line in rendered:
                buf.append(f"{line}\033[K\n")
            sys.stdout.write("".join(buf))
            sys.stdout.flush()
            await asyncio.sleep(0.5)
    finally:
        # Show cursor on exit
        sys.stdout.write("\033[?25h\n")
        sys.stdout.flush()
