"""
MethodId 3 redirect handler.

When the gate server is done, it sends a NotifyEnterWorld Notify packet
containing the scene server's IP, port, and a handover token that replaces
the JWT for the reconnect login.
"""

import asyncio
import logging
from dataclasses import dataclass

from core.zrpc import unwrap_tag1
from proto.codec import decode_notify_enter_world

log = logging.getLogger(__name__)


@dataclass
class RedirectInfo:
    ip:    str
    port:  int
    token: str   # handover token — use instead of JWT for reconnect login
    line_id: int


def parse_redirect(payload: bytes) -> RedirectInfo:
    """Parse a MethodId-3 Notify payload into a RedirectInfo."""
    data = decode_notify_enter_world(unwrap_tag1(payload))

    info = RedirectInfo(
        ip      = data["scene_ip"],
        port    = data["scene_port"],
        token   = data["token"],
        line_id = data["line_id"],
    )
    if info.ip and info.port:
        log.info(f"[Redirect] → {info.ip}:{info.port}  line={info.line_id}")
    else:
        log.info(f"[Redirect] Same-server re-login (line switch)")
    return info


async def open_scene_connection(redirect: RedirectInfo) -> tuple:
    """
    Open a fresh TCP connection to the scene server.
    Returns (reader, writer) ready for login with the handover token.
    """
    log.info(f"[Redirect] Connecting to scene server {redirect.ip}:{redirect.port}")
    reader, writer = await asyncio.open_connection(redirect.ip, redirect.port)
    return reader, writer
