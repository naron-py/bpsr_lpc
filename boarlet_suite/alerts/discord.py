"""
Discord alert system.

Sends rich embeds to a webhook when a Loyal Boarlet is confirmed.
Dedup key: (boarlet_id, line_id, hour_bucket) — one alert per location per hour.
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone

import aiohttp

log = logging.getLogger(__name__)

EMBED_COLOR   = 0xFF6600   # orange
RATE_LIMIT_DELAY = 1.0     # seconds between webhook calls to avoid 429


@dataclass
class Alert:
    boarlet_id: int
    line_id:    int
    slot_id:    int
    spawn_name: str


async def discord_sender(
    discord_queue: asyncio.Queue,
    webhook_url:   str,
) -> None:
    """
    Drain discord_queue and POST each alert as a rich embed.
    Runs forever — intended to be gathered alongside BotClient coroutines.
    """
    seen: set[tuple] = set()

    async with aiohttp.ClientSession() as session:
        while True:
            alert: Alert = await discord_queue.get()
            try:
                hour_bucket = int(time.time() // 3600)
                dedup_key   = (alert.boarlet_id, alert.line_id, hour_bucket)

                if dedup_key in seen:
                    log.debug(f"[Discord] Dedup — line={alert.line_id} already alerted this hour")
                    continue

                await _send_embed(session, webhook_url, alert)
                seen.add(dedup_key)

                # Prune old buckets to keep memory bounded
                current_hour = int(time.time() // 3600)
                seen = {k for k in seen if k[2] >= current_hour - 1}

                await asyncio.sleep(RATE_LIMIT_DELAY)

            except Exception as e:
                log.warning(f"[Discord] Failed to send alert: {e}")
            finally:
                discord_queue.task_done()


async def _send_embed(
    session:     aiohttp.ClientSession,
    webhook_url: str,
    alert:       Alert,
) -> None:
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    embed = {
        "title":  "Loyal Boarlet Spotted!",
        "color":  EMBED_COLOR,
        "fields": [
            {"name": "World Line", "value": str(alert.line_id),   "inline": True},
            {"name": "Location",   "value": alert.spawn_name,     "inline": True},
            {"name": "Bot Slot",   "value": f"#{alert.slot_id}",  "inline": True},
            {"name": "Time",       "value": now_str,              "inline": True},
        ],
        "footer": {"text": "BPTimer Boarlet Suite"},
    }

    payload = {"embeds": [embed]}

    async with session.post(
        webhook_url,
        json=payload,
        timeout=aiohttp.ClientTimeout(total=10),
    ) as resp:
        if resp.status == 204:
            log.info(
                f"[Discord] Alert sent — line={alert.line_id} "
                f"spawn={alert.spawn_name}"
            )
        elif resp.status == 429:
            retry_after = float((await resp.json()).get("retry_after", 1))
            log.warning(f"[Discord] Rate limited — retry after {retry_after}s")
            await asyncio.sleep(retry_after)
            await _send_embed(session, webhook_url, alert)   # one retry
        else:
            body = await resp.text()
            log.warning(f"[Discord] Unexpected status {resp.status}: {body[:200]}")
