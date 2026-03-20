"""
Hand-rolled Protobuf encoder/decoder for BPTimer Boarlet Suite.
Covers only the messages the bot sends and receives — no protoc required.
"""

# ── Wire types ────────────────────────────────────────────────────────────────
WT_VARINT = 0
WT_LEN    = 2


# ── Primitives ────────────────────────────────────────────────────────────────

def encode_varint(n: int) -> bytes:
    n = n & 0xFFFFFFFFFFFFFFFF  # treat as unsigned 64-bit
    buf = []
    while n > 0x7F:
        buf.append((n & 0x7F) | 0x80)
        n >>= 7
    buf.append(n)
    return bytes(buf)


def decode_varint(data: bytes, pos: int) -> tuple[int, int]:
    result, shift = 0, 0
    while True:
        b = data[pos]; pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7


def encode_field_varint(field_num: int, value: int) -> bytes:
    return encode_varint((field_num << 3) | WT_VARINT) + encode_varint(value)


def encode_field_bool(field_num: int, value: bool) -> bytes:
    return encode_field_varint(field_num, 1 if value else 0)


def encode_field_bytes(field_num: int, data: bytes) -> bytes:
    tag = encode_varint((field_num << 3) | WT_LEN)
    return tag + encode_varint(len(data)) + data


def encode_field_string(field_num: int, s: str) -> bytes:
    return encode_field_bytes(field_num, s.encode("utf-8"))


def encode_field_message(field_num: int, msg: bytes) -> bytes:
    return encode_field_bytes(field_num, msg)


def parse_fields(data: bytes) -> dict:
    """
    Parse raw protobuf bytes into {field_num: [values]} dict.
    All length-delimited fields stored as raw bytes.
    Repeated fields accumulate into a list.
    """
    fields: dict[int, list] = {}
    pos = 0
    while pos < len(data):
        tag, pos = decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07

        if wire_type == WT_VARINT:
            value, pos = decode_varint(data, pos)
            fields.setdefault(field_num, []).append(value)

        elif wire_type == WT_LEN:
            length, pos = decode_varint(data, pos)
            value = data[pos:pos + length]
            pos += length
            fields.setdefault(field_num, []).append(value)

        elif wire_type == 1:   # 64-bit fixed (double/fixed64/sfixed64)
            pos += 8

        elif wire_type == 5:   # 32-bit fixed (float/fixed32/sfixed32)
            pos += 4

        else:
            # Wire types 3/4 (deprecated groups) or 6/7 (invalid) — stop
            break

    return fields


def first(fields: dict, num: int, default=None):
    vals = fields.get(num)
    return vals[0] if vals else default


def first_str(fields: dict, num: int, default: str = "") -> str:
    v = first(fields, num)
    if v is None:
        return default
    return v.decode("utf-8") if isinstance(v, bytes) else default


def first_int(fields: dict, num: int, default: int = 0) -> int:
    v = first(fields, num)
    return v if isinstance(v, int) else default


# ── Message encoders ──────────────────────────────────────────────────────────

def encode_request_connect_world(
    account_id: str,
    token: str,
    game_version: str,
    client_resource_version: str,
    os_enum: int,
    ack_server_sequence: int = 0,
    session_token: str = "",
) -> bytes:
    """
    Encode RequestConnectWorld for Blue Protocol SEA.

    Confirmed field map from live packet capture:
      field 1  = account_id              (string, e.g. "6_345895410")
      field 3  = token                   (string, 36-char GUID session token)
      field 4  = ack_server_sequence     (varint, used in scene login — echoes packet count)
      field 5  = session_token           (string, from gate ConnectWorldResult — used in scene login)
      field 7  = game_version            (string, e.g. "1.0.35794.0")
      field 8  = client_resource_version (string, e.g. "0.0.32499.35794")
      field 9  = os                      (varint enum, 5 observed on Windows client)

    Gate login: only fields 1, 3, 7, 8, 9 (same as before).
    Scene login: adds field 4 (ack_server_sequence) and field 5 (session_token from gate).
    """
    buf = b""
    buf += encode_field_string(1, account_id)
    buf += encode_field_string(3, token)
    if ack_server_sequence:
        buf += encode_field_varint(4, ack_server_sequence)
    if session_token:
        buf += encode_field_string(5, session_token)
    if game_version:
        buf += encode_field_string(7, game_version)
    if client_resource_version:
        buf += encode_field_string(8, client_resource_version)
    if os_enum:
        buf += encode_field_varint(9, os_enum)
    return buf


def encode_connect_world(
    account_id: str,
    token: str,
    game_version: str,
    client_resource_version: str,
    os_enum: int,
    ack_server_sequence: int = 0,
    session_token: str = "",
) -> bytes:
    """Wrap RequestConnectWorld in the outer ConnectWorld.v_request field."""
    inner = encode_request_connect_world(
        account_id, token, game_version, client_resource_version, os_enum,
        ack_server_sequence=ack_server_sequence,
        session_token=session_token,
    )
    return encode_field_message(1, inner)


def encode_confirm_login(agent_guid: str, connect_guid: str) -> bytes:
    """
    Encode the ReqConfirmLogin post-login handshake.
    
    Wire layout (from capture):
      field 1: agentGuid
      field 2: 44
      field 3: connect_guid (from ConnectWorldResult)
    """
    inner = b""
    inner += encode_field_string(1, agent_guid)
    inner += encode_field_varint(2, 44)
    inner += encode_field_string(3, connect_guid)
    return encode_field_message(1, inner)


def encode_transfer_param(scene_id: int, transfer_type: int = 0,
                           change_flag: int = 0, is_server_switch: bool = False) -> bytes:
    buf = encode_field_varint(1, scene_id)
    if transfer_type:
        buf += encode_field_varint(2, transfer_type)
    if change_flag:
        buf += encode_field_varint(4, change_flag)
    if is_server_switch:
        buf += encode_field_bool(5, is_server_switch)
    return buf


_SWITCH_LINE_PREFIX = b'\x00\x05\x00\x02'   # 4-byte inner-frame header observed in captures


def encode_switch_line(line_id: int) -> bytes:
    """
    Encode the inner-frame payload for an explicit World Line switch.

    Confirmed format from live capture (switching to WL 1, 6, 10, 20, 30):
      00 05 00 02 0a 02 10 XX
      ^^^^^^^^^^^^            = 4-byte prefix (constant for line switches)
                  ^^^^^^^^^^  = field1(bytes({field2: varint(line_id)}))

    For line_id=1  → 000500020a021001
    For line_id=6  → 000500020a021006
    For line_id=10 → 000500020a02100a

    This payload goes directly into an inner ZRPC frame (via encode_inner_frame),
    which is then wrapped in a FrameUp outer packet (via encode_frame_up).
    No tag1 wrapping is applied to inner-frame payloads.
    """
    inner = encode_field_varint(2, line_id)    # TransferParam.field2 = line_id
    proto = encode_field_message(1, inner)      # outer field1 wraps TransferParam
    return _SWITCH_LINE_PREFIX + proto


def encode_req_switch_scene(scene_id: int, transfer_type: int = 0,
                             change_flag: int = 0) -> bytes:
    """
    Encode the proto body of a ReqSwitchScene inner-frame payload.

    Observed wire (after 4-byte prefix `00 05 00 02`):
      field1 → TransferParam { field1: scene_id }
    That is: encode_field_message(1, encode_transfer_param(scene_id))
    = `0a 02 08 XX`  (for single-byte scene_ids)

    The caller (scanner.py) must prepend the 4-byte inner-frame prefix
    `\\x00\\x05\\x00\\x02` before sending this inside a FrameUp inner call.
    """
    param = encode_transfer_param(scene_id, transfer_type, change_flag)
    return encode_field_message(1, param)


def encode_load_map_success(scene_guid: str, connect_guid: str,
                            aoi_sync_count: int = 0) -> bytes:
    """
    Encode LoadMapSuccess { LoadMapSuccessParam v_param = 1 }.

    LoadMapSuccessParam fields (from Il2Cpp dump):
      field 1: scene_guid    (string)
      field 2: aoi_sync_count (int32)
      field 3: connect_guid  (string)
    """
    param = b""
    if scene_guid:
        param += encode_field_string(1, scene_guid)
    if aoi_sync_count:
        param += encode_field_varint(2, aoi_sync_count)
    if connect_guid:
        param += encode_field_string(3, connect_guid)
    return encode_field_message(1, param)


def encode_transfer_loading_end() -> bytes:
    """Encode TransferLoadingEnd — empty message, no fields."""
    return b""


# ── Post-login setup burst (from capture 2026-03-18) ─────────────────────────

# Routing prefixes for inner-frame calls observed in live capture.
# Each FrameUp Call payload = 4-byte prefix + protobuf body.
_PREFIX_SCENE_ENTER     = b'\x00\x05\x10\x02'   # initial scene enter (field 1 = scene_id)
_PREFIX_SYNC_04c01f     = b'\x00\x04\xc0\x1f'   # unknown sync (empty proto)
_PREFIX_SYNC_048001     = b'\x00\x04\x80\x01'   # unknown sync (empty proto)
_PREFIX_SYNC_05e001     = b'\x00\x05\xe0\x01'   # unknown sync (field 3 = 11)
_PREFIX_SYNC_05a001     = b'\x00\x05\xa0\x01'   # unknown sync (no proto)
_PREFIX_SYNC_011002     = b'\x00\x01\x10\x02'   # unknown sync (no proto)
_PREFIX_SCENE_026002    = b'\x00\x02\x60\x02'   # scene data (field 2 = char_id varint)
_PREFIX_SYNC_04d001     = b'\x00\x04\xd0\x01'   # pre-confirm sync (empty proto)
_PREFIX_SYNC_01a00b     = b'\x00\x01\xa0\x0b'   # re-login only sync (empty proto)
_PREFIX_SYNC_050001     = b'\x00\x05\x00\x01'   # unknown sync (empty proto)
_PREFIX_CHAR_047065     = b'\x00\x04\x70\x65'   # char sync (field 2 = char_id varint)


def encode_scene_enter(scene_id: int) -> bytes:
    """Encode initial scene enter payload: prefix 0x051002 + field1(field1(scene_id))."""
    inner = encode_field_varint(1, scene_id)
    return _PREFIX_SCENE_ENTER + encode_field_message(1, inner)


def encode_fight_value_sync() -> bytes:
    """
    Encode FightValueSyncFromClient (Notify 0x36001) payload.

    First thing the real client sends after ConnectWorldResult.
    Hardcoded from capture — dummy combat stat values.
    """
    return bytes.fromhex(
        "12143336337c37397c307c3233307c34327c307c31320a18"
        "466967687456616c756553796e6346726f6d436c69656e74"
    )


def encode_char_scene_data(char_id: int) -> bytes:
    """Encode prefix 0x026002 call with char_id (field 1 = {field 2 = char_id})."""
    inner = encode_field_varint(2, char_id)
    return _PREFIX_SCENE_026002 + encode_field_message(1, inner)


def encode_char_sync_047065(char_id: int) -> bytes:
    """Encode prefix 0x047065 call with char_id (field 1 = {field 1 = char_id})."""
    inner = encode_field_varint(1, char_id)
    return _PREFIX_CHAR_047065 + encode_field_message(1, inner)


def encode_setup_burst_initial(scene_id: int, char_id: int) -> list[list]:
    """
    Build the post-ConfirmLogin setup burst for initial login.

    Returns a list of batch groups. Each group is a list of
    (payload_bytes, is_notify, notify_method_id) tuples.
    Each group maps to one FrameUp packet (batched inner frames).

    Matches the live capture (2026-03-18) exactly:
      FrameUp ch=3: Notify 0x3003 + 6 Calls
      FrameUp ch=4: Notify 0x8002 + Call 0x011002
      FrameUp ch=5: (skipped — entity position, requires entity ID)
      FrameUp ch=6: Call 0x047065 + Call 0x050001
    """
    # Batch 1 → FrameUp ch=3 (7 inner frames)
    batch_3 = [
        (b"", True, 0x3003),                          # Notify 0x3003 (empty)
        (encode_char_scene_data(char_id), False, 0),   # Call 0x026002 with char_id
        (_PREFIX_SYNC_04c01f + b'\x0a\x00', False, 0), # Call 0x04c01f (empty)
        (_PREFIX_SYNC_048001 + b'\x0a\x00', False, 0), # Call 0x048001 (empty)
        (_PREFIX_SYNC_05e001 + b'\x0a\x02\x18\x0b', False, 0),  # Call 0x05e001 (f3=11)
        (_PREFIX_SYNC_05a001, False, 0),                # Call 0x05a001 (no proto)
        (encode_scene_enter(scene_id), False, 0),       # Call 0x051002 scene enter
    ]

    # Batch 2 → FrameUp ch=4 (2 inner frames)
    batch_4 = [
        (b'\x12\x01\x00\x08\xd9\x02', True, 0x8002),  # Notify 0x8002
        (_PREFIX_SYNC_011002, False, 0),                 # Call 0x011002
    ]

    # Batch 3 → FrameUp ch=6 (2 inner frames)
    batch_6 = [
        (encode_char_sync_047065(char_id), False, 0),   # Call 0x047065 with char_id
        (_PREFIX_SYNC_050001 + b'\x0a\x00', False, 0),  # Call 0x050001 (empty)
    ]

    return [batch_3, batch_4, batch_6]


def encode_setup_burst_relogin(scene_id: int) -> list[list]:
    """
    Build the post-ConfirmLogin setup burst for re-login
    (after line-switch redirect + ConnectWorld re-login).

    Returns a list with a single batch group (all calls in one FrameUp).
    """
    batch = [
        (_PREFIX_SYNC_04c01f + b'\x0a\x00', False, 0),
        (_PREFIX_SYNC_01a00b + b'\x0a\x00', False, 0),
        (_PREFIX_SYNC_048001 + b'\x0a\x00', False, 0),
        (_PREFIX_SYNC_05e001 + b'\x0a\x02\x18\x0b', False, 0),
        (_PREFIX_SYNC_05a001, False, 0),
        (encode_scene_enter(scene_id), False, 0),
        (_PREFIX_SYNC_011002, False, 0),
    ]
    return [batch]


def decode_enter_scene(data: bytes) -> dict:
    """
    Parse EnterScene → extract scene_guid and connect_guid.

    EnterScene { EnterSceneInfo enter_scene_info = 1 }
    EnterSceneInfo {
      AttrCollection scene_attrs = 1;
      Entity player_ent = 2;
      string scene_guid = 3;
      string connect_guid = 4;
    }
    """
    outer = parse_fields(data)
    info_bytes = first(outer, 1, b"")
    if not info_bytes:
        return {"scene_guid": "", "connect_guid": ""}
    f = parse_fields(info_bytes)
    return {
        "scene_guid":   first_str(f, 3),
        "connect_guid": first_str(f, 4),
    }


# ── Message decoders ──────────────────────────────────────────────────────────

def decode_connect_world_result(data: bytes) -> dict:
    f = parse_fields(data)
    return {
        "result":              first_int(f, 1),
        "err_code":            first_int(f, 2),
        "ack_client_sequence": first_str(f, 3),
        "session_token":       first_str(f, 4),
        "connect_guid":        first_str(f, 5),
    }


def decode_notify_enter_world(data: bytes) -> dict:
    """Parse NotifyEnterWorld → NotifyEnterWorldRequest."""
    outer = parse_fields(data)
    inner_bytes = first(outer, 1, b"")
    f = parse_fields(inner_bytes)
    return {
        "account_id": first_str(f, 1),
        "token":      first_str(f, 2),
        "scene_ip":   first_str(f, 3),
        "scene_port": first_int(f, 4),
        "line_id":    _decode_scene_line_data(first(f, 6, b"")),
    }


def _decode_scene_line_data(data: bytes) -> int:
    if not data:
        return 0
    f = parse_fields(data)
    return first_int(f, 1)


def decode_sync_container_data(data: bytes) -> dict:
    """
    Parse SyncContainerData → extract line_id, char_id, and name.

    SyncContainerData { CharSerialize v_data = 1 }
    CharSerialize { char_id=1, char_base=2, scene_data=3, ... }
    SceneData { ..., line_id=15, ... }
    CharBaseInfo { char_id=1, account_id=2, name=5, ... }
    """
    outer = parse_fields(data)
    v_data_bytes = first(outer, 1, b"")
    if not v_data_bytes:
        return {}

    char = parse_fields(v_data_bytes)
    result = {"char_id": first_int(char, 1)}

    # CharBaseInfo (field 2)
    base_bytes = first(char, 2, b"")
    if base_bytes:
        base = parse_fields(base_bytes)
        result["name"] = first_str(base, 5)
        result["account_id"] = first_str(base, 2)

    # SceneData (field 3)
    scene_bytes = first(char, 3, b"")
    if scene_bytes:
        scene = parse_fields(scene_bytes)
        result["line_id"] = first_int(scene, 15)

    return result


def decode_sync_near_entities(data: bytes) -> list[dict]:
    """
    Parse SyncNearEntities → list of {uuid, ent_type, base_id}.
    base_id extracted from AttrItem where id == ATTR_ID (10).
    """
    ATTR_ID   = 10   # AttrId — monster base_id
    ENT_MONSTER = 2

    outer = parse_fields(data)
    entities = []

    for appear_bytes in outer.get(1, []):   # repeated EntityAppear
        ef = parse_fields(appear_bytes)
        ent_type = first_int(ef, 2)
        if ent_type != ENT_MONSTER:
            continue

        uuid = first_int(ef, 1)
        base_id = None

        attrs_bytes = first(ef, 3, b"")
        if attrs_bytes:
            af = parse_fields(attrs_bytes)
            for attr_bytes in af.get(1, []):   # repeated AttrItem
                item = parse_fields(attr_bytes)
                if first_int(item, 1) == ATTR_ID:
                    raw = first(item, 2, b"")
                    if raw:
                        base_id, _ = decode_varint(raw, 0)
                    break

        if base_id is not None:
            entities.append({"uuid": uuid, "ent_type": ent_type, "base_id": base_id})

    return entities
