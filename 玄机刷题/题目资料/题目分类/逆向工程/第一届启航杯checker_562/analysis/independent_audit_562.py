from pathlib import Path
import struct, re, hashlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
P=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\第一届启航杯checker_562\analysis\extracted\checker.exe')
b=P.read_bytes()
def u16(o): return struct.unpack_from('<H',b,o)[0]
def u32(o): return struct.unpack_from('<I',b,o)[0]
def u64(o): return struct.unpack_from('<Q',b,o)[0]
assert b[:2]==b'MZ'
peoff=u32(0x3c); assert b[peoff:peoff+4]==b'PE\0\0'
coff=peoff+4; machine=u16(coff); nsec=u16(coff+2); optsize=u16(coff+16); opt=coff+20; magic=u16(opt)
pe32plus=magic==0x20b
imagebase=u64(opt+24) if pe32plus else u32(opt+28)
ep_rva=u32(opt+16); secalign=u32(opt+32); filealign=u32(opt+36); sizeimage=u32(opt+56)
print('file',P,'length',len(b),'sha256',hashlib.sha256(b).hexdigest().upper())
print(f'PE machine=0x{machine:04x} sections={nsec} optional_magic=0x{magic:04x} PE32+={pe32plus}')
print(f'imagebase=0x{imagebase:x} entry_rva=0x{ep_rva:x} entry_va=0x{imagebase+ep_rva:x} size_image=0x{sizeimage:x} align(sec/file)=0x{secalign:x}/0x{filealign:x}')
secs=[]
so=opt+optsize
for i in range(nsec):
 o=so+i*40; name=b[o:o+8].split(b'\0')[0].decode('ascii','replace'); vs,va,rs,rp=struct.unpack_from('<IIII',b,o+8); ch=u32(o+36)
 secs.append((name,va,max(vs,rs),rp,rs,ch)); print(f'SECTION {name!r} RVA=0x{va:x} virtual={vs} raw=0x{rp:x}+{rs} chars=0x{ch:x}')
def rvaoff(rva):
 if rva < u32(opt+60): return rva
 for name,va,extent,rp,rs,ch in secs:
  if va<=rva<va+extent:
   off=rp+(rva-va)
   if off < len(b): return off
 return None
# imports
idir=opt+(112 if pe32plus else 96)+8
irva=u32(idir); isz=u32(idir+4)
print(f'IMPORT directory rva=0x{irva:x} size=0x{isz:x}')
if irva:
 d=rvaoff(irva); nimp=0
 while d is not None and d+20<=len(b):
  oft,ts,fc,nm,ft=struct.unpack_from('<IIIII',b,d)
  if not (oft|ts|fc|nm|ft): break
  no=rvaoff(nm); dll=b[no:b.find(b'\0',no)].decode('ascii','replace') if no is not None else '?'
  print('DLL',dll)
  thunk_rva=oft or ft; to=rvaoff(thunk_rva); ptr=8 if pe32plus else 4; high=1<<(ptr*8-1)
  funcs=[]
  if to is not None:
   for j in range(512):
    val=u64(to+j*ptr) if ptr==8 else u32(to+j*ptr)
    if not val: break
    if val & high: funcs.append('#'+str(val&0xffff))
    else:
     no2=rvaoff(val & (high-1)); funcs.append(b[no2+2:b.find(b'\0',no2+2)].decode('ascii','replace') if no2 is not None else f'RVA_{val:x}')
  print('  imports:',', '.join(funcs)); nimp+=len(funcs); d+=20
 print('total named/ordinal imports',nimp)
# printable strings
print('=== ASCII strings >= 4 ===')
for m in re.finditer(rb'[\x20-\x7e]{4,}',b):
 s=m.group().decode('ascii','replace')
 print(f'0x{m.start():x}: {s[:240]}')
print('=== UTF-16LE strings >= 4 ===')
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){4,}',b):
 s=m.group().decode('utf-16le','replace')
 print(f'0x{m.start():x}: {s[:200]}')
# Entry disassembly
codeoff=rvaoff(ep_rva)
print('=== Entry disassembly, first 0x240 bytes ===')
print('entry file offset',codeoff)
if codeoff is not None:
 arch=CS_MODE_64 if pe32plus else CS_MODE_32
 md=Cs(CS_ARCH_X86,arch); md.detail=True
 va=imagebase+ep_rva
 for i in md.disasm(b[codeoff:codeoff+0x240],va):
  print(f'{i.address:#x}: {i.bytes.hex():<24} {i.mnemonic:<8} {i.op_str}')
