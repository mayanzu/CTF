from pathlib import Path
import struct,sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_MEM,X86_REG_RIP,X86_OP_IMM
p=Path(sys.argv[1]);d=p.read_bytes();pe=struct.unpack_from("<I",d,0x3c)[0];o=pe+24;base=struct.unpack_from("<Q",d,o+24)[0];n=struct.unpack_from("<H",d,pe+6)[0];os=struct.unpack_from("<H",d,pe+20)[0];st=o+os;S=[]
for i in range(n):
 q=st+i*40;nm=d[q:q+8].split(b"\0",1)[0].decode("ascii","replace");vs,rv,rs,rp=struct.unpack_from("<IIII",d,q+8);fl=struct.unpack_from("<I",d,q+36)[0];S.append((nm,rv,rs,rp,fl))
def va2fo(va):
 r=va-base
 for nm,rv,rs,rp,fl in S:
  if rv<=r<rv+rs:return rp+r-rv
 return None
needles=["Palu_996!?","flag","}","palu{","1145141919810","Success","Failed"]
targets=[]
for s in needles:
 raw=s.encode("utf-16le")+b"\0\0";cur=0
 while (fo:=d.find(raw,cur))>=0:
  va=next((base+rv+fo-rp for nm,rv,rs,rp,fl in S if rp<=fo<rp+rs),None)
  if va: print(f"string={s!r} file=0x{fo:x} va=0x{va:x}");targets.append((s,va,va+len(raw)))
  cur=fo+1
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
for nm,rv,rs,rp,fl in S:
 if not(fl&0x20000000) or not rs:continue
 print(f"--- {nm} ---")
 for i in md.disasm(d[rp:rp+rs],base+rv):
  refs=[]
  for op in i.operands:
   if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:refs.append(i.address+i.size+op.mem.disp)
   elif op.type==X86_OP_IMM:refs.append(op.imm)
  for s,a,b in targets:
   if any(a<=x<b for x in refs):print(f"0x{i.address:x}: {i.mnemonic:<8} {i.op_str} -> {s!r}")
