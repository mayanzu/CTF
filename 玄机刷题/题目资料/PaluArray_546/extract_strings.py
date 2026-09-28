from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
data = path.read_bytes()
print(f"file={path} bytes={len(data)}")
for kind, pattern in (("ascii", rb"[\x20-\x7e]{4,}"), ("utf16le", rb"(?:[\x20-\x7e]\x00){4,}")):
    print(f"--- {kind} strings ---")
    for match in re.finditer(pattern, data):
        raw = match.group(0)
        text = raw.decode("ascii" if kind == "ascii" else "utf-16le", errors="replace")
        print(f"0x{match.start():06x}: {text}")
