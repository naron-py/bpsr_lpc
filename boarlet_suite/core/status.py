"""
Shared bot status — updated by BotClient, read by the dashboard.
"""

from collections import deque
from dataclasses import dataclass, field
import time


@dataclass
class BotStatus:
    slot: int
    spawn_name: str
    state: str = "Starting"
    current_line: int = 0
    lines_scanned: int = 0
    total_alive: int = 0
    total_dead: int = 0
    alerts_found: int = 0
    cycle_count: int = 0
    started_at: float = field(default_factory=time.monotonic)
    server: str = ""
    error: str = ""
    events: deque = field(default_factory=lambda: deque(maxlen=50))

    def event(self, msg: str) -> None:
        ts = time.strftime("%H:%M:%S")
        self.events.append(f"{ts}  #{self.slot} {msg}")
