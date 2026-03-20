import os
import sys

# add boarlet_suite to path for proto imports
sys.path.insert(0, r"C:\Users\Fade\Desktop\BPSR\bpsr_lpc\boarlet_suite")

from proto.codec import parse_fields, decode_varint
import zstandard as zstd
import struct

log_file = r"C:\Users\Fade\Desktop\BPSR\bpsr_lpc\boarlet_suite\tools\proxy_log.txt"

hex_data = ""
with open(log_file, "r") as f:
    lines = f.readlines()
    for line in lines:
        if "payload (1847 bytes):" in line:
            hex_data = line.split("payload (1847 bytes):")[1].strip()

# decomp
decompressor = zstd.ZstdDecompressor()
payload = bytes(bytearray.fromhex(hex_data))
# proxy_log.txt chopped off the first 4 bytes of zstd stream (28 b5 2f fd) thinking it was method_id
payload = b'\x28\xb5\x2f\xfd' + payload
print(f"Payload to decompress: {len(payload)}")
decompressed = decompressor.decompress(payload)

fields = parse_fields(decompressed)

def find_char_id(data, target=51817459):
    try:
        f = parse_fields(data)
    except Exception:
        return
    for k, vals in f.items():
        for v in vals:
            if isinstance(v, int) and v == target:
                print(f"FOUND CHAR_ID {target} at key {k}!")
            elif isinstance(v, bytes):
                # check if it's the target varint directly
                try:
                    num, _ = decode_varint(v, 0)
                    if num == target:
                        print(f"FOUND CHAR_ID {target} inside bytes key {k}!")
                except Exception:
                    pass
                find_char_id(v, target)

find_char_id(decompressed)

# Let's also print the structure to understand the base keys
print(f"Top level keys: {list(fields.keys())}")
if 1 in fields:
    f1 = parse_fields(fields[1][0])
    print(f"f1 keys: {list(f1.keys())}")
    if 2 in f1:
         f1_2 = parse_fields(f1[2][0])
         print(f"f1.f2 keys: {list(f1_2.keys())}")
