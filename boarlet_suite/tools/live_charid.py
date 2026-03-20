import asyncio
import json
import sys

sys.path.insert(0, r"C:\Users\Fade\Desktop\BPSR\bpsr_lpc\boarlet_suite")

from core.gate_auth import _build_jwt_packet, _read_auth_packet, _extract_session_blob, _decode_session_blob, load_jwt

async def main():
    with open(r"C:\Users\Fade\Desktop\BPSR\bpsr_lpc\boarlet_suite\config.json", "r") as f:
        cfg = json.load(f)
    
    auth_ip = cfg["auth_ip"]
    jwt = load_jwt(cfg)
    
    reader, writer = await asyncio.open_connection(auth_ip, 5003)
    frame1 = _build_jwt_packet(jwt)
    writer.write(frame1)
    await writer.drain()
    
    resp1 = await _read_auth_packet(reader)
    session_blob = _extract_session_blob(resp1)
    
    if session_blob:
        session_data = _decode_session_blob(session_blob)
        print("====== SESSION DATA ======")
        print(json.dumps(session_data, indent=2))
        print("==========================")
        
        # Decompress resp1 to find 51817459
        import zstandard as zstd
        decompressor = zstd.ZstdDecompressor()
        raw = resp1[18:] # skip 18 byte header
        
        with decompressor.stream_reader(raw) as rdr:
            dec = rdr.read()
            
        print(f"Successfully decompressed {len(dec)} bytes.")
        
        from proto.codec import parse_fields, decode_varint
        def find_char_id(data, target=51817459, path="root"):
            try:
                f = parse_fields(data)
            except Exception:
                return
            for k, vals in f.items():
                for v in vals:
                    if isinstance(v, int) and v == target:
                        print(f"FOUND CHAR_ID {target} at path {path}.{k}!")
                    elif isinstance(v, bytes):
                        try:
                            num, _ = decode_varint(v, 0)
                            if num == target:
                                print(f"FOUND CHAR_ID {target} inside bytes at path {path}.{k}!")
                        except Exception:
                            pass
                        find_char_id(v, target, path + f".{k}")

        print("Searching for 51817459 in decompressed payload...")
        find_char_id(dec)
        
        # Test my new robust extraction logic:
        print("====== ROBUST EXTRACTION TEST ======")
        char_id_extracted = 0
        try:
            f = parse_fields(dec)
            f1 = parse_fields(f.get(1, [b""])[0])
            f2 = parse_fields(f1.get(2, [b""])[0])
            f7_raw = f2.get(7, [b""])[0]
            if f7_raw:
                f7 = parse_fields(f7_raw)
                char_id_extracted = f7.get(1, [0])[0]
        except Exception as e:
            print(f"Error extracting charId: {e}")
        
        print(f"Extracted char_id: {char_id_extracted}")
    else:
        print("No session blob found!")

if __name__ == "__main__":
    asyncio.run(main())
