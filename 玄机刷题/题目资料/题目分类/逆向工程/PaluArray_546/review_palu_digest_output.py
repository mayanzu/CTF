from pathlib import Path
import struct,sys
sys.stdout.reconfigure(encoding='utf-8',errors='backslashreplace')
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
p=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluArray_546\PaluArray_flag_unpacked.exe');d=p.read_bytes();pe=struct.unpack_from('<I',d,0x3c)[0];opt=pe+24;base=struct.unpack_from('<Q',d,opt+24)[0];n=struct.unpack_from('<H',d,pe+6)[0];st=opt+struct.unpack_from('<H',d,pe+20)[0];secs=[]
for i in range(n):
 q=st+i*40;nm=d[q:q+8].split(b'\0',1)[0].decode('ascii','replace');vs,rv,rs,rp=struct.unpack_from('<IIII',d,q+8);secs.append((nm,vs,rv,rs,rp))
def fo(r):
 for nm,vs,rv,rs,rp in secs:
  if rv<=r<rv+rs:return rp+r-rv
 raise KeyError(hex(r))
md=Cs(CS_ARCH_X86,CS_MODE_64)
for a,b in [(0x14d8,0x1700),(0x2d70,0x2e40),(0x1a48,0x1d96)]:
 print(f'\n=== RVA {a:#x}..{b:#x} ===')
 for i in md.disasm(d[fo(a):fo(a)+b-a],base+a): print(f'{i.address-base:06x} {i.bytes.hex():<22} {i.mnemonic:<8} {i.op_str}')
