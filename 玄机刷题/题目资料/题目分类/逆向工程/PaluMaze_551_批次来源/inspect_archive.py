from pathlib import Path
import struct

path = Path(__file__).with_name("game_flag.exe")
data = path.read_bytes()
cookie_size = 88
magic, package_len, toc_offset, toc_len, pyver, py_dll = struct.unpack("!8sIIII64s", data[-cookie_size:])
if magic != bytes.fromhex("4d45490c0b0a0b0e"):
    raise SystemExit(f"Unexpected cookie magic: {magic.hex()}")
package_start = len(data) - package_len
toc = data[package_start + toc_offset : package_start + toc_offset + toc_len]
print(f"file_size={len(data)} package_start={package_start} package_len={package_len} toc_offset={toc_offset} toc_len={toc_len} python={pyver} dll={py_dll.split(bytes([0]))[0].decode()}")
print("entry | type | compressed | offset | stored | original | name")
pos = 0
idx = 0
while pos < len(toc):
    entry_size, offset, stored_len, original_len, compressed, type_code = struct.unpack("!iIIIBc", toc[pos : pos + 18])
    if entry_size < 18 or pos + entry_size > len(toc):
        raise SystemExit(f"Bad TOC entry at {pos}: size={entry_size}")
    name = toc[pos + 18 : pos + entry_size].split(bytes([0]), 1)[0].decode("utf-8", "replace")
    print(f"{idx:03} | {type_code.decode(errors='replace')} | {compressed} | {offset} | {stored_len} | {original_len} | {name}")
    pos += entry_size
    idx += 1
print(f"entries={idx} parsed_toc_bytes={pos}")
