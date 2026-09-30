from pathlib import Path
import struct
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_OP_MEM
from capstone.x86_const import X86_REG_RIP
b=(Path(__file__).resolve().parents[1]/'analysis'/'PaluArray_flag_unpacked_repro.exe').read_bytes(); pe=struct.unpack_from('<I',b,0x3c)[0];base=struct.unpack_from('<Q',b,pe+24+24)[0]; sh=pe+24+struct.unpack_from('<H',b,pe+20)[0]; secs=[]
for i in range(struct.unpack_from('<H',b,pe+6)[0]):
 s=sh+40*i;n=b[s:s+8].split(b'\0')[0].decode();vs,va,rs,rp=struct.unpack_from('<IIII',b,s+8);secs.append((n,va,rs,rp))
def off(rva):
 for n,va,rs,rp in secs:
  if va<=rva<va+rs:return rp+rva-va
 raise ValueError(hex(rva))
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True;text=next(x for x in secs if x[0]=='.text'); n,va,rs,rp=text
print('ImageBase',hex(base),'global alphabet object RVA 0x9b48')
print('=== all RIP xrefs to globals RVAs 0x9000..0xa000 ===')
for i in md.disasm(b[rp:rp+rs],base+va):
 for op in i.operands:
  if op.type==CS_OP_MEM and op.mem.base==X86_REG_RIP:
   tv=i.address+i.size+op.mem.disp
   if 0x140009000<=tv<0x14000a000:print(f'{i.address-base:#x} -> {tv-base:#x}: {i.mnemonic} {i.op_str}')
for a,z in [(0x1000,0x10a0),(0x19b0,0x1a30),(0x1020,0x1060)]:
 print('=== code',hex(a),hex(z),'===')
 for i in md.disasm(b[off(a):off(z)],base+a):print(f'{i.address-base:06x}: {i.mnemonic:<8} {i.op_str}')
