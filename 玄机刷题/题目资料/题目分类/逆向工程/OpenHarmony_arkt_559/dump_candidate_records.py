import struct
from pathlib import Path
b=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\OpenHarmony_arkt_559\附件解包\HAP内容\ets\modules.abc').read_bytes()
class_offsets=[struct.unpack_from('<I',b,0x3c+4*i)[0] for i in range(12)]
method_offsets=[struct.unpack_from('<I',b,0x6c+4*i)[0] for i in range((0xc0-0x6c)//4)]

def dump(label,offs,n):
 print(label)
 for off in offs:
  print(f'-- fileoff=0x{off:04x} --')
  for p in range(off,min(off+n,len(b)),16):
   row=b[p:min(p+16,off+n,len(b))]
   asc=''.join(chr(x) if 32<=x<127 else '.' for x in row)
   print(f'{p:04x}: {row.hex(" "):47} {asc}')

dump('CLASS_INDEX_CANDIDATES',class_offsets,48)
dump('METHOD_INDEX_CANDIDATES',method_offsets,40)
