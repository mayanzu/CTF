from pathlib import Path
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

path=Path(sys.argv[1]); data=path.read_bytes(); pe=struct.unpack_from("<I",data,0x3c)[0]; opt=pe+24
base=struct.unpack_from("<Q",data,opt+24)[0]; n=struct.unpack_from("<H",data,pe+6)[0]; osz=struct.unpack_from("<H",data,pe+20)[0]; st=opt+osz
secs=[]
for i in range(n):
 o=st+i*40; name=data[o:o+8].split(b"\0",1)[0].decode("ascii","replace"); vs,rva,rs,rp=struct.unpack_from("<IIII",data,o+8); flags=struct.unpack_from("<I",data,o+36)[0]; secs.append((name,rva,rs,rp,flags))
def va_to_file(va):
 rva=va-base
 for name,srva,rs,rp,flags in secs:
  if srva<=rva<srva+rs: return rp+rva-srva
 return None
for start_rva,end_rva in ((0x1d80,0x1f60),(0x1700,0x1900)):
 print(f"--- RVA 0x{start_rva:x}..0x{end_rva:x} ---")
 fo=va_to_file(base+start_rva)
 md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
 for ins in md.disasm(data[fo:fo+(end_rva-start_rva)],base+start_rva):
  refs=[]
  for op in ins.operands:
   if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
    va=ins.address+ins.size+op.mem.disp; ref=va_to_file(va)
    if ref is not None:
     raw=data[ref:ref+48]
     s=raw.decode("utf-16le",errors="ignore").split("\x00",1)[0]
     if s and any(c.isalpha() for c in s): refs.append(f"; -> {s!r} VA=0x{va:x}")
  print(f"0x{ins.address:x}: {ins.mnemonic:<8} {ins.op_str} {' '.join(refs)}")
