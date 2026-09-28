from pathlib import Path
import struct,sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
p=Path(sys.argv[1]); start=int(sys.argv[2],16); end=int(sys.argv[3],16); d=p.read_bytes(); pe=struct.unpack_from('<I',d,0x3c)[0]; opt=pe+24; base=struct.unpack_from('<Q',d,opt+24)[0]; n=struct.unpack_from('<H',d,pe+6)[0]; os=struct.unpack_from('<H',d,pe+20)[0]; table=opt+os; sections=[]
for j in range(n):
 q=table+j*40; name=d[q:q+8].split(b'\0',1)[0].decode('ascii','replace'); vs,rv,rs,rp=struct.unpack_from('<IIII',d,q+8); sections.append((name,rv,rs,rp))
def off(rva):
 for name,rv,rs,rp in sections:
  if rv<=rva<rv+rs:return rp+rva-rv
 raise ValueError(hex(rva))
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
for i in md.disasm(d[off(start):off(end-1)+1],base+start): print(f'0x{i.address:x}: {i.mnemonic:<8} {i.op_str}')
