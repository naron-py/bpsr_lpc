import asyncio
import json
import logging
import sys

# setup logging explicitly to stdout
logging.basicConfig(level=logging.INFO, stream=sys.stdout)
log = logging.getLogger(__name__)

async def run():
    sys.path.insert(0, r"c:\Users\Fade\Desktop\BPSR\bpsr_lpc\boarlet_suite")
    from core.client import BotClient
    from alerts.discord import discord_sender
    
    with open("config.json", "r") as f:
        cfg = json.load(f)
    # force IP just to be sure
    # force IP to proxy server
    cfg["gate_ip"] = "172.65.161.68"

    print("Running BotClient...")
    q = asyncio.Queue()
    bot = BotClient(cfg["bots"][0], cfg, q, set())
    
    # We will just run session directly to bypass the infinite while loop
    try:
        await bot._session()
    except Exception as e:
        print(f"CRASH: {e}")

asyncio.run(run())
