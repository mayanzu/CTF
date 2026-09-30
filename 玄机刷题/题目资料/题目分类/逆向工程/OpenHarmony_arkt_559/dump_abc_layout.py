import struct
from pathlib import Path
p=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\OpenHarmony_arkt_559\附件解包\HAP内容\ets\modules.abc')
b=p.read_bytes()
print('FILE=',p)
print('SIZE=',len(b))
print('MAGIC=',repr(b[:8]))
print('HEADER_DWORDS_LE:')
for off in range(0, min(0x100,len(b)),4):
 v=struct.unpack_from('<I',b,off)[0]
 print(f'{off:04x}: {v:10d} (0x{v:08x}) bytes={b[off:off+4].hex()}')
print('HEADER_HEX_ROWS:')
for off in range(0, min(0x100,len(b)),16):
 row=b[off:off+16]
 asc=''.join(chr(x) if 32<=x<127 else '.' for x in row)
 print(f'{off:04x}: {row.hex(" "):47} {asc}')
print('KNOWN_SECTION_WINDOWS:')
for center in [0x3c,0xc0,0x2800,0x3000,0x3800,0x5000,0x5500]:
 lo=max(0,center-32); hi=min(len(b),center+96)
 print(f'-- 0x{lo:x}..0x{hi:x} --')
 for off in range(lo,hi,16):
  row=b[off:min(off+16,hi)]
  print(f'{off:04x}: {row.hex(" "):47}')
