# BPTimer Boarlet Suite

Python bot ecosystem for Blue Protocol (SEA Server) — scans 70+ World Lines for Loyal Boarlet spawns.

## Quick Reference

```bash
python main.py tcp      # 8 headless TCP bots scanning in parallel
python main.py win32    # Win32 PostMessage control of game client windows
```

## Project Structure

```
boarlet_suite/
├── main.py                  # Mode selector: tcp | win32
├── config.json              # All runtime config — tokens, lines, webhook, UI coords
├── proto/
│   ├── bp.proto             # Trimmed protobuf schema (messages bot uses only)
│   └── bp_pb2.py            # Generated — run: protoc --python_out=. proto/bp.proto
├── core/
│   ├── zrpc.py              # Wire encoding: 4-byte header, wrap_tag1/unwrap_tag1
│   ├── client.py            # BotClient — one asyncio coroutine per slot
│   ├── login.py             # ConnectWorld (0x1002) login, JWT injection
│   ├── scanner.py           # ReqSwitchScene loop, SyncNearEntities parser
│   └── redirect.py          # MethodId 3 handler — reconnect to scene server
├── detection/
│   ├── engine.py            # Alert filter: (now - last_update) > 20h OR last_hp > 0
│   └── api_client.py        # db.bptimer.com aiohttp client
├── alerts/
│   └── discord.py           # Webhook sender, rich embed, dedup by (id, line, hour)
├── win32_bot/
│   ├── controller.py        # find_game_windows(), post_key(), post_click()
│   └── actions.py           # open_world_map(), switch_line(), confirm_switch()
└── data/
    └── packet_traces/       # slot_0.json … slot_7.json — captured login packets
```

## Protocol Essentials

### Wire Frame (all values big-endian)
```
[4]  total length (includes these 4 bytes)
[2]  packet_type  — bit15=zstd, bits0-14=MessageType (1=Call 2=Notify 3=Return 6=FrameDown)
[8]  service_uuid — always 0x0000000063335342
[4]  request_id
[4]  method_id
[N]  protobuf payload (zstd-decompress first if bit15 set)
```

### SEA Wrapping
- **Outbound Call payloads**: `wrap_tag1(proto_bytes)` before framing
- **Inbound Return/Notify payloads**: `unwrap_tag1(raw)` before Protobuf decode
- Field tag: `0x0A` (field 1, wire type 2 = length-delimited)

### Key Method IDs
| Method | ID | Direction |
|---|---|---|
| ConnectWorld (login) | 0x1002 | Call (outbound) |
| Server redirect | 3 | Notify (inbound) |
| SyncNearEntities | 0x06 | Notify (inbound) |

### Key Proto Messages
| Message | Purpose |
|---|---|
| `ConnectWorld` | Login wrapper |
| `RequestConnectWorld` | Login body — inject `token` (field 3), copy rest from trace |
| `ConnectWorldResult` | Login response — `session_token` (field 4), `connect_guid` (field 5) |
| `NotifyEnterWorld` | Redirect — contains `scene_ip`, `scene_port`, handover `token` |
| `ReqSwitchScene` | Switch World Line — `TransferParam.scene_id` = line scene ID |
| `SyncNearEntities` | Entity snapshot — parse for Loyal Boarlet `base_id` |

## Config (`config.json`)

```json
{
  "gate_ip": "...",
  "gate_port": 0,
  "discord_webhook": "https://discord.com/api/webhooks/...",
  "bptimer_api_url": "https://db.bptimer.com",
  "loyal_boarlet_id": 0,
  "lines": [1001, 1002],
  "bots": [
    {
      "slot": 0,
      "spawn_name": "Kana Village",
      "account_id": "...",
      "char_id": "...",
      "token": "...",
      "trace_file": "data/packet_traces/slot_0.json"
    }
  ],
  "win32": {
    "line_btn_x": 0, "line_btn_y": 0,
    "line_list_x": 0, "line_list_y": 0,
    "line_row_height": 30,
    "confirm_btn_x": 0, "confirm_btn_y": 0
  }
}
```

## Detection Logic

```
Loyal Boarlet in SyncNearEntities?
  → Query db.bptimer.com for (boarlet_id, line_id)
  → Alert if: (now - last_update) > 20 hours  OR  last_hp > 0
  → Dedup key: (boarlet_id, line_id, hour_bucket) — one alert per hour max
```

## Things That Must Come From Packet Traces

- `scene_id` values per World Line (in `TransferParam.scene_id`)
- `LOYAL_BOARLET_ID` (monster base_id)
- MethodId for `ReqSwitchScene`
- `client_resource_version` and `os` fields in `RequestConnectWorld` — copy verbatim, do not regenerate

## Dependencies

```
protobuf>=4.0
aiohttp>=3.9
zstandard>=0.22
pywin32>=306    # win32 mode only
```

Install: `pip install -r requirements.txt`
Regenerate proto: `protoc --python_out=. proto/bp.proto`

## Reference

- Full proto schema: `../bptimer/apps/desktop/reference/pb_complete.proto`
- Existing Rust protocol impl: `../bptimer/apps/desktop/src/capture/`
- Protocol constants: `../bptimer/apps/desktop/src/protocol/constants.rs`
- Design doc: `docs/plans/2026-03-15-boarlet-suite-design.md`
