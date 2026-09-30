from pathlib import Path
import struct
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
P=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\第一届启航杯checker_562\analysis\extracted\checker.exe'); b=P.read_bytes(); base=0x400000
u16=lambda o:struct.unpack_from('<H',b,o)[0]; u32=lambda o:struct.unpack_from('<I',b,o)[0]
pe=u32(0x3c); coff=pe+4; nsec=u16(coff+2); osz=u16(coff+16); opt=coff+20; magic=u16(opt); ib=u32(opt+28); so=opt+osz
secs=[]
for i in range(nsec):
 o=so+40*i; name=b[o:o+8].split(b'\0')[0]; vs,va,rs,rp=struct.unpack_from('<IIII',b,o+8); secs.append((va,max(vs,rs),rp,rs))
def off(rva):
 for va,extent,rp,rs in secs:
  if va<=rva<va+extent: return rp+rva-va
 return None
idir=opt+96+8; rva=u32(idir); d=off(rva)
print('=== imported IAT addresses ===')
while d is not None:
 oft,ts,fc,nm,ft=struct.unpack_from('<IIIII',b,d)
 if not(oft|ts|fc|nm|ft): break
 no=off(nm); dll=b[no:b.find(b'\0',no)].decode('ascii','replace'); print(dll)
 th=off(oft or ft); i=0
 while True:
  v=u32(th+4*i)
  if not v: break
  if v&0x80000000: name='#'+str(v&0xffff)
  else:
   q=off(v); name=b[q+2:b.find(b'\0',q+2)].decode('ascii','replace')
  print(f'  IAT {ib+ft+4*i:#x}: {name}')
  i+=1
 d+=20
print('=== wrapper disassembly, aligned from .text base ===')
md=Cs(CS_ARCH_X86,CS_MODE_32); insns=list(md.disasm(b[0x400:0x400+11776],0x401000))
for i in insns:
 if 0x403b40<=i.address<0x403be0: print(f'{i.address:#x}: {i.bytes.hex():<16} {i.mnemonic:<8} {i.op_str}')
