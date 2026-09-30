import struct,sys
from pathlib import Path
p=Path(sys.argv[1]); b=p.read_bytes()
read=lambda o: struct.unpack_from('<I',b,o)[0]
class_count=read(0x1c); method_count=read(0x2c); method_index=read(0x30)
print(f'FILE={p} size={len(b)} classes={class_count} class_index=0x3c methods={method_count} method_index=0x{method_index:x}')
for label,offs,n in [('CLASS', [read(0x3c+4*i) for i in range(class_count)], 64), ('METHOD', [read(method_index+4*i) for i in range(method_count)], 48)]:
 print(label)
 for i,off in enumerate(offs):
  raw=b[off:min(off+n,len(b))]
  asc=''.join(chr(x) if 32<=x<127 else '.' for x in raw)
  print(f'{i:03} @0x{off:06x}: {raw.hex(" ")} | {asc}')
