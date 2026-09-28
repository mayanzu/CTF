from pathlib import Path
import sys

path = Path(sys.argv[1])
data = path.read_bytes()
for start, end in ((0x42f0, 0x43b0), (0x5d90, 0x5e30)):
    raw = data[start:end]
    print(f"--- file offset 0x{start:x}..0x{end:x} ---")
    print(raw.hex(" "))
    print("utf16le:", raw.decode("utf-16le", errors="replace"))
