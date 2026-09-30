import struct,sys
from pathlib import Path
b=Path(sys.argv[1]).read_bytes()
pe=struct.unpack_from('<I',b,0x3c)[0]; n=struct.unpack_from('<H',b,pe+6)[0]; ol=struct.unpack_from('<H',b,pe+20)[0]; opt=pe+24; image=struct.unpack_from('<Q',b,opt+24)[0]; sb=opt+ol
secs=[]
for i in range(n):
 o=sb+i*40; name=b[o:o+8].split(b'\0',1)[0].decode('ascii','replace'); vs,va,rs,rp=struct.unpack_from('<IIII',b,o+8); secs.append((name,va,rs,rp))
def off(va):
 rva=va-image
 for name,va0,rs,rp in secs:
  if va0<=rva<va0+rs:return rp+rva-va0
 raise ValueError(hex(va))
for table in (0x4daa10,0x4daa20,0x4daa30,0x4daa40):
 print(f'--- string header array at VA 0x{table:x} ---')
 o=off(table)
 for i in range(4):
  ptr,length=struct.unpack_from('<QQ',b,o+16*i)
  try:s=b[off(ptr):off(ptr)+length].decode('utf8','replace')
  except Exception as e:s=f'<decode error {e}>'
  print(f'[{i}] data=0x{ptr:x} len={length} text={s!r}')
for va,l in ((0x4b5de3,5),(0x4bf204,84),(0x4b6c18,12),(0x4b7d85,17)):
 print(f'VA 0x{va:x}, file offset 0x{off(va):x}, bytes={l}: {b[off(va):off(va)+l]!r}')
