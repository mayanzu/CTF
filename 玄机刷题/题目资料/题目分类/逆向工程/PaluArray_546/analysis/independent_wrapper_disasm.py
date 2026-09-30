from pathlib import Path
import struct
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
b=(Path(__file__).resolve().parents[1]/'analysis'/'PaluArray_flag_unpacked_repro.exe').read_bytes();pe=struct.unpack_from('<I',b,0x3c)[0];base=struct.unpack_from('<Q',b,pe+48)[0];sh=pe+24+struct.unpack_from('<H',b,pe+20)[0];secs=[]
for i in range(struct.unpack_from('<H',b,pe+6)[0]):
 s=sh+40*i;nm=b[s:s+8].split(b'\0')[0].decode();vs,va,rs,rp=struct.unpack_from('<IIII',b,s+8);secs.append((va,rs,rp))
def off(r):
 for va,sz,rp in secs:
  if va<=r<va+sz:return rp+r-va
md=Cs(CS_ARCH_X86,CS_MODE_64)
for a,z in [(0x14d8,0x1700),(0x1b24,0x1c8f)]:
 print(f'=== RVA {a:#x}-{z:#x} ===')
 for i in md.disasm(b[off(a):off(z)],base+a):print(f'{i.address-base:06x}: {i.mnemonic:<8} {i.op_str}')
