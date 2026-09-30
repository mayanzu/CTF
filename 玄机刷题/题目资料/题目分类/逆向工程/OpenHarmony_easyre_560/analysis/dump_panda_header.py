import struct,sys
from pathlib import Path
p=Path(sys.argv[1]); b=p.read_bytes()
print('FILE=',p); print('SIZE=',len(b)); print('MAGIC=',repr(b[:8]))
print('HEADER_DWORDS_LE:')
for off in range(0,min(0x100,len(b)),4):
 v=struct.unpack_from('<I',b,off)[0]; print(f'{off:04x}: {v:10d} (0x{v:08x}) bytes={b[off:off+4].hex()}')
print('HEADER_HEX_ROWS:')
for off in range(0,min(0x100,len(b)),16):
 row=b[off:off+16]; asc=''.join(chr(x) if 32<=x<127 else '.' for x in row); print(f'{off:04x}: {row.hex(" "):47} {asc}')
