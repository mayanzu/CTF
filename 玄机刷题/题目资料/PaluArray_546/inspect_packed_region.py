from pathlib import Path
import sys

data = Path(sys.argv[1]).read_bytes()
for start, length in ((0x400, 0x100), (0x3f00, 0x100), (0x7800, 0x100)):
    chunk = data[start:start+length]
    print(f"--- file offset 0x{start:x}, {len(chunk)} bytes ---")
    print(chunk.hex(" "))
    print("ascii:", "".join(chr(b) if 32 <= b < 127 else "." for b in chunk))
