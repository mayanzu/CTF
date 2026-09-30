#!/usr/bin/env python3
"""Extract DEX string-table entries and code points without executing the APK."""
import hashlib
import struct
import sys
from pathlib import Path

path = Path(sys.argv[1])
blob = path.read_bytes()
u32 = lambda off: struct.unpack_from('<I', blob, off)[0]
def uleb(off):
    value = shift = 0
    while True:
        c = blob[off]
        off += 1
        value |= (c & 0x7f) << shift
        if c < 0x80:
            return value, off
        shift += 7
def mutf8(off):
    _, off = uleb(off)
    end = blob.index(0, off)
    return blob[off:end].replace(b'\xc0\x80', b'\x00').decode('utf-8', 'replace')

count, table = u32(0x38), u32(0x3c)
print(f"FILE={path} SIZE={len(blob)} SHA256={hashlib.sha256(blob).hexdigest().upper()}")
print(f"STRING_COUNT={count}")
for i in range(count):
    s = mutf8(u32(table + 4*i))
    hexes = ' '.join(f'U+{ord(c):04X}' for c in s)
    print(f"[{i:03}] len={len(s):4} repr={s!r}")
    if s and any(ord(c) >= 0x600 for c in s):
        print(f"      CODEPOINTS={hexes}")
