# BPTimer Boarlet Suite — Design Document
**Date:** 2026-03-15
**Status:** Approved

---

## Overview

Distributed Python bot ecosystem for Blue Protocol (SEA Server) that scans 70+ World Lines
for Loyal Boarlet spawns and fires Discord alerts when found. Two independent operating modes:
**TCP** (headless pure-network) and **Win32** (game client window control).

---

## Architecture Decision

**Single asyncio process, 8 coroutines (Approach A)**

One Python process runs 8 `asyncio` coroutines. Each coroutine manages its own TCP connection
and independently cycles all 70+ World Lines. Each bot's character is pre-parked at one of
8 named spawn locations — together they give full location coverage on every line simultaneously.

Discord dedup and bptimer API check share in-memory state via `asyncio.Lock`.

---

## Project Structure

```
boarlet_suite/
│
├── main.py                  # Entrypoint — mode selector (tcp | win32)
├── config.json              # JWT tokens, bot slots, Discord webhook, API key
├── requirements.txt
│
├── proto/
│   ├── bp.proto             # Trimmed schema: only messages the bot sends/receives
│   └── bp_pb2.py            # Generated (protoc)
│
├── core/
│   ├── zrpc.py              # ZRPC framing: 4-byte header, encode/decode, wrap_tag1/unwrap_tag1
│   ├── client.py            # Single bot TCP connection (asyncio) — one instance per slot
│   ├── login.py             # ConnectWorld (0x1002) login flow, token injection
│   ├── scanner.py           # ReqSwitchScene loop, SyncNearEntities parser
│   └── redirect.py          # MethodId 3 handler — extract IP/Port/token, reconnect
│
├── detection/
│   ├── engine.py            # Boarlet detection: query bptimer API, apply alert filter
│   └── api_client.py        # db.bptimer.com HTTP client (aiohttp)
│
├── alerts/
│   └── discord.py           # Rich embed builder + webhook sender, dedup guard
│
├── win32_bot/
│   ├── controller.py        # PostMessage-based game window control
│   └── actions.py           # High-level actions: open_world_map, switch_line, confirm_switch
│
├── data/
│   └── packet_traces/       # Captured JSON login traces (loaded at startup)
│       └── slot_{n}.json    # One file per bot slot
│
└── docs/
    └── plans/
        └── 2026-03-15-boarlet-suite-design.md
```

---

## Protocol: Wire Frame Layout

Confirmed from existing Rust implementation (`bptimer/apps/desktop/src/capture/`).

```
Offset  Size  Field
──────────────────────────────────────────────────────────────
0       4     total packet length (BE uint32, includes these 4 bytes)
4       2     packet_type: bit15=zstd flag, bits0-14=MessageType
              1=Call, 2=Notify, 3=Return, 6=FrameDown
6       8     service_uuid = 0x0000000063335342  (ASCII "c3SB")
14      4     request_id (echoed back in Return)
18      4     method_id
22      N     protobuf payload (optionally zstd-compressed)
```

---

## Protocol: SEA wrap_tag1 / unwrap_tag1

SEA server requires outbound Call payloads wrapped as protobuf field 1 (tag=0x0A, wire=2).

```python
def wrap_tag1(inner: bytes) -> bytes:
    return b'\x0a' + encode_varint(len(inner)) + inner

def unwrap_tag1(data: bytes) -> bytes:
    assert data[0] == 0x0a
    length, offset = decode_varint(data, 1)
    return data[offset : offset + length]
```

Applied to **outbound Call payloads only**.
Inbound Return/Notify payloads are unwrapped before Protobuf decode.

---

## Protobuf Schema (`proto/bp.proto`)

### Login (MethodId 0x1002)

```protobuf
message ConnectWorld { RequestConnectWorld v_request = 1; }

message RequestConnectWorld {
  string account_id              = 1;
  string char_id                 = 2;
  string token                   = 3;  // JWT injected from config.json
  string ack_server_sequence     = 4;  // from captured trace
  bool   is_ai_bot               = 6;
  string client_resource_version = 8;  // from captured trace
  string os                      = 9;  // from captured trace
}

message ConnectWorldResult {
  int32  result              = 1;
  int32  err_code            = 2;
  string ack_client_sequence = 3;
  string session_token       = 4;  // SEA session string
  string connect_guid        = 5;  // SEA session GUID
}
```

### Server Redirect (MethodId 3 Notify)

```protobuf
message NotifyEnterWorld { NotifyEnterWorldRequest v_request = 1; }

message NotifyEnterWorldRequest {
  string        account_id      = 1;
  string        token           = 2;  // handover token — replaces JWT on reconnect
  string        scene_ip        = 3;  // new server IP
  int32         scene_port      = 4;  // new server port
  TransferParam transform       = 5;
  SceneLineData scene_line_data = 6;
}

message SceneLineData {
  uint32 line_id    = 1;
  int32  status     = 2;
  string scene_guid = 3;
}
```

### Line Switch

```protobuf
message ReqSwitchScene     { SwitchSceneRequest resp          = 1; }
message SwitchSceneRequest { TransferParam      transfer_param = 1; }

message TransferParam {
  int32 scene_id         = 1;  // World Line scene ID — from packet traces
  int32 transfer_type    = 2;
  int64 change_flag      = 4;
  bool  is_server_switch = 5;
}
```

### Entity Detection (MethodId 0x06)

```protobuf
message SyncNearEntities   { repeated EntityAppear appear = 1; }
message EntityAppear       { int64 uuid = 1; int32 ent_type = 2; AttrCollection attrs = 3; }
message AttrCollection     { repeated AttrItem attrs = 1; }
message AttrItem           { int32 id = 1; bytes raw_data = 2; }
// AttrId = 10 (0x0A) → monster base_id (varint)
// Loyal Boarlet base_id → confirmed from packet traces
```

---

## Bot Lifecycle State Machine

```
DISCONNECTED
    │ asyncio.open_connection(gate_ip, gate_port)
    ▼
CONNECTED
    │ send ConnectWorld(0x1002) with injected JWT
    ▼
AUTHENTICATING
    │ recv ConnectWorldResult → store session_token + connect_guid
    ▼
IN_WORLD
    │ loop: send ReqSwitchScene(scene_id=lines[i])
    │       wait for SyncNearEntities → check base_id == LOYAL_BOARLET_ID
    │       on MethodId 3 Notify → REDIRECTING
    ▼
REDIRECTING
    │ extract scene_ip, scene_port, handover_token
    │ close socket → reconnect → login with handover_token
    ▼
IN_WORLD (scene server) ──► continue scan loop
```

---

## Detection Engine

**Alert condition:** `(now - last_update) > 20 hours  OR  last_hp > 0`

1. Bot detects `base_id == LOYAL_BOARLET_ID` in `SyncNearEntities`
2. Query `db.bptimer.com` for last record of this boarlet + line (60s cache)
3. Apply filter — if condition met, push to `alert_queue`
4. Single Discord sender coroutine drains queue → POST webhook

---

## Discord Alert Embed

Fields: **World Line**, **Location** (named spawn from config), **Bot Slot**, **Time**
Dedup key: `(boarlet_id, line_id, hour_bucket)` — no re-alert within same hour.

---

## Win32 Mode

- Uses `PostMessage` exclusively — no `SetForegroundWindow`, no focus stealing
- UI coordinates (map button, line list positions) stored in `config.json["win32"]`
- One coroutine per detected game window, paired to bot slot by discovery order

---

## Config Schema (`config.json`)

```json
{
  "gate_ip": "...",
  "gate_port": 0,
  "discord_webhook": "...",
  "bptimer_api_url": "https://db.bptimer.com",
  "loyal_boarlet_id": 0,
  "lines": [1001, 1002, 1003],
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
    "line_row_height": 0,
    "confirm_btn_x": 0, "confirm_btn_y": 0
  }
}
```

---

## Key Implementation Notes

1. `scene_id` values per World Line — must be confirmed from packet traces in `data/packet_traces/`
2. `LOYAL_BOARLET_ID` — confirm from traces or existing Rust constants
3. MethodId for `ReqSwitchScene` — confirm from traces (user specified 0x1002 for ConnectWorld)
4. `db.bptimer.com` boarlet query endpoint — follows PocketBase pattern from existing Rust client
5. `RequestConnectWorld` fields 8+9 (`client_resource_version`, `os`) — copy verbatim from trace, do not regenerate

---

## Dependencies

```
protobuf>=4.0
aiohttp>=3.9
zstandard>=0.22
pywin32>=306          # win32 mode only
```
