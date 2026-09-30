#!/usr/bin/env python3
"""Summarize obfuscated strings from the app DEX without running the APK."""
import collections
import struct
import sys
import unicodedata
from pathlib import Path

blob = Path(sys.argv[1]).read_bytes()
u32 = lambda off: struct.unpack_from('<I', blob, off)[0]
def uleb(off):
    value = shift = 0
    while True:
        c = blob[off]; off += 1
        value |= (c & 0x7f) << shift
        if c < 0x80: return value, off
        shift += 7
def getstr(off):
    _, off = uleb(off)
    end = blob.index(0, off)
    return blob[off:end].replace(b'\xc0\x80', b'\x00').decode('utf-8', 'replace')

count, table = u32(0x38), u32(0x3c)
strings = [getstr(u32(table + 4*i)) for i in range(count)]
print(f"DEX_STRINGS={len(strings)}")
for i, s in enumerate(strings):
    if i < 34:
        continue
    freq = collections.Counter(s)
    hist = ','.join(f'U+{ord(ch):04X}:{n}' for ch,n in sorted(freq.items(), key=lambda x: ord(x[0])))
    print(f"IDX={i:03} LEN={len(s)} UNIQUE={len(freq)} HIST={hist}")
    print("  PREFIX=" + ' '.join(f'{ord(ch):04X}' for ch in s[:48]))
print("\nGLOBAL_CHARACTER_NAMES")
allfreq = collections.Counter(ch for s in strings[34:] for ch in s)
for ch,n in sorted(allfreq.items(), key=lambda x: ord(x[0])):
    print(f"U+{ord(ch):04X} count={n} name={unicodedata.name(ch, '<unnamed>')}")
