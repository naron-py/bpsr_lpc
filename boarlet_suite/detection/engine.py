"""
Boarlet detection engine.

Alert condition: (now - last_update) > 20 hours  OR  last_hp > 0

This runs as a single coroutine that drains the raw_queue produced by
scanner coroutines, applies the filter, and forwards passing alerts to
the discord_queue.
"""

import asyncio
import logging
import time

from detection.api_client import BPTimerAPIClient

log = logging.getLogger(__name__)

ALERT_THRESHOLD_HOURS = 20
ALERT_THRESHOLD_SEC   = ALERT_THRESHOLD_HOURS * 3600


async def detection_loop(
    raw_queue:     asyncio.Queue,   # incoming from scanner (Alert objects)
    discord_queue: asyncio.Queue,   # outgoing to discord sender
    api_client:    BPTimerAPIClient,
) -> None:
    """
    Consume raw detections, query the API, forward confirmed alerts.
    Runs forever — intended to be gathered alongside BotClient coroutines.
    """
    while True:
        alert = await raw_queue.get()
        try:
            should = await _should_alert(alert.boarlet_id, alert.line_id, api_client)
            if should:
                await discord_queue.put(alert)
                log.info(
                    f"[Detection] Alert queued — line={alert.line_id} "
                    f"spawn={alert.spawn_name}"
                )
            else:
                log.debug(
                    f"[Detection] Suppressed — line={alert.line_id} "
                    f"(recently reported, HP=0)"
                )
        except Exception as e:
            log.warning(f"[Detection] Error processing alert: {e}")
        finally:
            raw_queue.task_done()


async def _should_alert(
    boarlet_id: int,
    line_id:    int,
    api_client: BPTimerAPIClient,
) -> bool:
    record = await api_client.get_boarlet_record(boarlet_id, line_id)

    if record is None:
        return True   # no prior record → always alert

    stale = (time.time() - record["last_update"]) > ALERT_THRESHOLD_SEC
    alive = record["last_hp"] > 0
    return stale or alive
