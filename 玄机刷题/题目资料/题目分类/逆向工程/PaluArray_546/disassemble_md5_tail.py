from pathlib import Path
import struct,sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
p=Path(sys.argv[1]);d=p.read_bytes();pe=struct.unpack_from("<I",d,0x3c)[0];o=pe+24;base=struct.unpack_from("<Q",d,o+24)[0];n=struct.unpack_from("<H",d,pe+6)[0];os=struct.unpack_from("<H",d,pe+20)[0];st=o+os;S=[]
for i in range(n):
 q=st+i*40;nm=d[q:q+8].split(b"\0",1)[0].decode("ascii","replace");vs,rv,rs,rp=struct.unpack_from("<IIII",d,q+8);S.append((nm,rv,rs,rp))
def fo(va):
 r=va-base
 for nm,rv,rs,rp in S:
  if rv<=r<rv+rs:return rp+r-rv
 raise ValueError(hex(va))
md=Cs(CS_ARCH_X86,CS_MODE_64)
for a,b in ((0x1b00,0x1d80),(0x2230,0x2290),(0x2410,0x24c0)):
 print(f"--- RVA 0x{a:x}..0x{b:x} ---")
 for i in md.disasm(d[fo(base+a):fo(base+a)+(b-a)],base+a):print(f"0x{i.address:x}: {i.mnemonic:<8} {i.op_str}")
