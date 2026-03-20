"""
Win32 game window controller.

Uses PostMessage exclusively — never SetForegroundWindow or SendMessage.
Game windows are never brought into focus.
"""

import logging
import time

log = logging.getLogger(__name__)

try:
    import win32gui
    import win32con
    import win32api
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    log.warning("[Win32] pywin32 not installed — win32 mode unavailable")


def _require_win32() -> None:
    if not WIN32_AVAILABLE:
        raise RuntimeError("pywin32 is not installed. Run: pip install pywin32")


def find_game_windows(title_substr: str = "Blue Protocol") -> list[int]:
    """
    Return list of HWNDs whose window title contains title_substr.
    Searches all visible top-level windows.
    """
    _require_win32()
    windows = []

    def _cb(hwnd, _):
        if win32gui.IsWindowVisible(hwnd):
            title = win32gui.GetWindowText(hwnd)
            if title_substr in title:
                windows.append(hwnd)

    win32gui.EnumWindows(_cb, None)
    log.info(f"[Win32] Found {len(windows)} game window(s)")
    return windows


def post_key(hwnd: int, vk_code: int, delay_ms: int = 50) -> None:
    """
    Post WM_KEYDOWN + WM_KEYUP to hwnd without stealing focus.
    delay_ms: milliseconds between down and up (simulates key hold).
    """
    _require_win32()
    win32api.PostMessage(hwnd, win32con.WM_KEYDOWN, vk_code, 0)
    time.sleep(delay_ms / 1000)
    win32api.PostMessage(hwnd, win32con.WM_KEYUP, vk_code, 0)


def post_click(hwnd: int, x: int, y: int) -> None:
    """
    Post WM_LBUTTONDOWN + WM_LBUTTONUP at client coordinates (x, y).
    No focus change — works on background windows.
    """
    _require_win32()
    lparam = win32api.MAKELONG(x, y)
    win32api.PostMessage(hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam)
    time.sleep(0.03)
    win32api.PostMessage(hwnd, win32con.WM_LBUTTONUP, 0, lparam)


def post_char(hwnd: int, char: str) -> None:
    """Post a WM_CHAR message for a single character."""
    _require_win32()
    win32api.PostMessage(hwnd, win32con.WM_CHAR, ord(char), 0)
