from pathlib import Path
import struct,sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
p=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\PaluArray_546\PaluArray_flag_unpacked.exe'); d=p.read_bytes()
pe=struct.unpack_from('<I',d,0x3c)[0]; opt=pe+24; base=struct.unpack_from('<Q',d,opt+24)[0]; n=struct.unpack_from('<H',d,pe+6)[0]; st=opt+struct.unpack_from('<H',d,pe+20)[0]
secs=[]
for i in range(n):
 q=st+i*40; nm=d[q:q+8].split(b'\0',1)[0].decode('ascii','replace'); vs,rv,rs,rp=struct.unpack_from('<IIII',d,q+8); secs.append((nm,vs,rv,rs,rp))
def fo(r):
 for nm,vs,rv,rs,rp in secs:
  if rv<=r<rv+rs:return rp+r-rv
 raise KeyError(hex(r))
md=Cs(CS_ARCH_X86,CS_MODE_64)
for a,b in [(0x1d90,0x1f70),(0x1f6c,0x2118),(0x2118,0x2244),(0x2244,0x2404)]:
 print(f'\n=== RVA {a:#x}..{b:#x} ===')
 f=fo(a)
 for x in md.disasm(d[f:f+b-a],base+a): print(f'{x.address-base:06x} {x.bytes.hex():<22} {x.mnemonic:<8} {x.op_str}')
