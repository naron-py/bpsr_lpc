"""
High-level Win32 bot actions for Blue Protocol.

All UI coordinates are loaded from config.json["win32"].
Update those values once by recording them from your screen.
"""

import asyncio
import logging

import win32con

from win32_bot.controller import post_key, post_click
from alerts.discord import Alert

log = logging.getLogger(__name__)


async def open_world_map(hwnd: int) -> None:
    """Open the in-game world map (default key: M)."""
    post_key(hwnd, ord("M"))
    await asyncio.sleep(0.5)


async def close_world_map(hwnd: int) -> None:
    post_key(hwnd, win32con.VK_ESCAPE)
    await asyncio.sleep(0.3)


async def switch_line(hwnd: int, line_index: int, w32_cfg: dict) -> None:
    """
    Click through the World Line selector UI to switch to line_index (0-based).

    w32_cfg keys (from config.json["win32"]):
      line_btn_x, line_btn_y       — button that opens the line list
      line_list_x, line_list_y     — top of the line list
      line_row_height               — pixel height per row
      confirm_btn_x, confirm_btn_y — confirmation button
    """
    await open_world_map(hwnd)

    # Open line selector
    post_click(hwnd, w32_cfg["line_btn_x"], w32_cfg["line_btn_y"])
    await asyncio.sleep(0.3)

    # Click target line row
    target_y = w32_cfg["line_list_y"] + line_index * w32_cfg["line_row_height"]
    post_click(hwnd, w32_cfg["line_list_x"], target_y)
    await asyncio.sleep(0.2)

    # Confirm
    post_click(hwnd, w32_cfg["confirm_btn_x"], w32_cfg["confirm_btn_y"])
    await asyncio.sleep(1.5)   # wait for scene transition

    await close_world_map(hwnd)


async def win32_scan_loop(
    hwnd:        int,
    slot_cfg:    dict,
    global_cfg:  dict,
    alert_queue: asyncio.Queue,
) -> None:
    """
    Win32 mode scanning coroutine for one game window.

    Cycles through all configured World Lines by controlling the UI,
    then checks for Loyal Boarlet via the detection engine path.

    NOTE: Win32 mode cannot parse TCP packets directly — it relies on
    the user visually confirming or a separate lightweight packet sniffer.
    Push a manual alert to alert_queue if you see the Boarlet in-game.
    """
    w32_cfg = global_cfg.get("win32", {})
    lines   = global_cfg["lines"]

    log.info(f"[Win32 Bot{slot_cfg['slot']}] Starting scan on hwnd={hwnd}")

    line_idx = 0
    while True:
        scene_id = lines[line_idx % len(lines)]

        log.debug(
            f"[Win32 Bot{slot_cfg['slot']}] Switching to line index={line_idx} "
            f"scene_id={scene_id}"
        )

        try:
            await switch_line(hwnd, line_idx % len(lines), w32_cfg)
        except Exception as e:
            log.warning(f"[Win32 Bot{slot_cfg['slot']}] switch_line error: {e}")

        # Dwell on this line — increase if you need more time to spot the Boarlet
        await asyncio.sleep(global_cfg.get("win32_dwell_sec", 5.0))

        line_idx += 1
