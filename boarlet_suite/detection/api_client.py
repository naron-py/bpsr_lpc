"""
db.bptimer.com HTTP client (PocketBase API).

Fetches the latest HP record for a given monster + line to determine
whether a Discord alert should fire.
"""

import logging
import time
from datetime import datetime, timezone

import aiohttp

log = logging.getLogger(__name__)

# Cache TTL — avoid hitting the API on every detection within a short window
CACHE_TTL_SEC = 60.0


class BPTimerAPIClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self._session: aiohttp.ClientSession | None = None
        self._cache: dict[tuple, tuple[float, dict | None]] = {}

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                headers={"User-Agent": "BPTimerBoarletSuite/1.0"}
            )
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def get_boarlet_record(self, monster_id: int, line_id: int) -> dict | None:
        """
        Query the latest HP record for (monster_id, line_id).

        Returns dict with keys:
          last_update  — Unix timestamp (float) of last update
          last_hp      — HP percentage (int, 0-100)

        Returns None if no record found (treat as: always alert).
        """
        cache_key = (monster_id, line_id)
        now = time.monotonic()

        # Cache hit
        if cache_key in self._cache:
            cached_at, cached_val = self._cache[cache_key]
            if now - cached_at < CACHE_TTL_SEC:
                return cached_val

        result = await self._fetch_record(monster_id, line_id)
        self._cache[cache_key] = (now, result)
        return result

    async def _fetch_record(self, monster_id: int, line_id: int) -> dict | None:
        # PocketBase filter syntax — adjust collection name if different
        url = (
            f"{self.base_url}/api/collections/boarlet_hp/records"
            f"?filter=monster_id%3D{monster_id}%26%26line_id%3D{line_id}"
            f"&sort=-updated&perPage=1&skipTotal=true"
        )

        try:
            session = await self._get_session()
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 404:
                    return None
                if not resp.ok:
                    log.warning(f"[API] HTTP {resp.status} for monster={monster_id} line={line_id}")
                    return None

                data = await resp.json()
                items = data.get("items", [])
                if not items:
                    return None

                item = items[0]
                updated_str = item.get("updated", "")
                last_update = _parse_pb_timestamp(updated_str)

                return {
                    "last_update": last_update,
                    "last_hp":     int(item.get("hp_pct", 0)),
                }

        except Exception as e:
            log.warning(f"[API] Request failed for monster={monster_id} line={line_id}: {e}")
            return None


    async def get_dead_lines(
        self,
        mob_id: str = "flpn6xsffc0cvn3",
        region: str = "SEA",
        threshold_hours: float = 20.0,
    ) -> set[int]:
        """
        Fetch lines where the boarlet was killed < threshold_hours ago.
        Uses the mob_channel_status collection (same as boarlet_bot.py).
        Returns a set of line numbers to skip.
        """
        url = (
            f"{self.base_url}/api/collections/mob_channel_status/records"
            f"?perPage=200"
            f"&filter=mob%3D%27{mob_id}%27%20%26%26%20region%3D%27{region}%27"
            f"&skipTotal=1"
        )
        dead = set()
        try:
            session = await self._get_session()
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if not resp.ok:
                    log.warning(f"[API] Dead-lines HTTP {resp.status}")
                    return dead
                data = await resp.json()
                now = datetime.now(timezone.utc)
                for item in data.get("items", []):
                    hp = item.get("last_hp")
                    if hp is not None and hp <= 0.0:
                        line = item.get("channel_number")
                        updated_str = item.get("last_update") or item.get("updated")
                        if updated_str and line is not None:
                            dt = _parse_pb_timestamp_dt(updated_str)
                            if dt and (now - dt).total_seconds() / 3600.0 < threshold_hours:
                                dead.add(line)
        except Exception as e:
            log.warning(f"[API] Failed to fetch dead lines: {e}")
        return dead


def _parse_pb_timestamp(ts: str) -> float:
    """Parse PocketBase ISO timestamp → Unix float. Returns 0 on failure."""
    if not ts:
        return 0.0
    try:
        # PocketBase format: "2024-01-15 12:34:56.789Z"
        ts = ts.replace(" ", "T")
        if not ts.endswith("Z"):
            ts += "Z"
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.timestamp()
    except Exception:
        return 0.0


def _parse_pb_timestamp_dt(ts: str) -> datetime | None:
    """Parse PocketBase ISO timestamp → datetime. Returns None on failure."""
    if not ts:
        return None
    try:
        ts = ts.replace("Z", "+00:00").replace(" ", "T")
        return datetime.fromisoformat(ts)
    except Exception:
        try:
            dt_str = ts.split(".")[0]
            return datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        except Exception:
            return None
