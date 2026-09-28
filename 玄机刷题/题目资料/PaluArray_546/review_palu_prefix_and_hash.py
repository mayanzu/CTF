from pathlib import Path
import struct,hashlib,sys,re
sys.stdout.reconfigure(encoding='utf-8',errors='backslashreplace')
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_MEM,X86_REG_RIP
p=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluArray_546\PaluArray_flag_unpacked.exe');d=p.read_bytes()
pe=struct.unpack_from('<I',d,0x3c)[0];opt=pe+24;base=struct.unpack_from('<Q',d,opt+24)[0];n=struct.unpack_from('<H',d,pe+6)[0];st=opt+struct.unpack_from('<H',d,pe+20)[0];secs=[]
for j in range(n):
 q=st+j*40;nm=d[q:q+8].split(b'\0',1)[0].decode('ascii','replace');vs,rv,rs,rp=struct.unpack_from('<IIII',d,q+8);secs.append((nm,vs,rv,rs,rp))
def fo(rva):
 for nm,vs,rv,rs,rp in secs:
  if rv<=rva<rv+rs:return rp+rva-rv
 return None
def printable(b):return sum(32<=x<127 for x in b)/max(1,len(b))
imp_rva=struct.unpack_from('<I',d,opt+120)[0];imports={}
if imp_rva:
 pos=fo(imp_rva)
 while pos is not None:
  oft,ts,fc,nr,ft=struct.unpack_from('<IIIII',d,pos)
  if not (oft|nr|ft):break
  dll_off=fo(nr);dll=d[dll_off:].split(b'\0',1)[0].decode('ascii','replace');thunk=oft or ft;k=0
  while True:
   to=fo(thunk)+8*k;v=struct.unpack_from('<Q',d,to)[0]
   if not v:break
   nm=('ordinal_'+str(v&0xffff)) if v>>63 else d[fo(v)+2:].split(b'\0',1)[0].decode('ascii','replace')
   imports[base+ft+8*k]=dll+'!'+nm;k+=1
  pos+=20
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
for a,b in [(0x1994,0x1a48),(0x1a48,0x1d96),(0x1e4e,0x1ecb)]:
 print(f'\n=== RVA {a:#x}..{b:#x} ===')
 f=fo(a);chunk=d[f:f+(b-a)]
 for ins in md.disasm(chunk,base+a):
  extras=[]
  for op in ins.operands:
   if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
    va=ins.address+ins.size+op.mem.disp
    if va in imports:extras.append('IAT='+imports[va])
    off=fo(va-base)
    if off is not None:
     raw=d[off:off+80]
     asc=raw.split(b'\0',1)[0]
     if asc and printable(asc[:min(len(asc),40)])>.85: extras.append('ASCII='+repr(asc[:48]))
     wide=raw.decode('utf-16le','ignore').split('\0',1)[0]
     if wide and sum(c.isprintable() for c in wide)/max(1,len(wide))>.80: extras.append('UTF16='+repr(wide[:40]))
  print(f'{ins.address-base:06x} {ins.bytes.hex():<22} {ins.mnemonic:<7} {ins.op_str}',(' ; '+' | '.join(extras) if extras else ''))
print('\nTARGETED LITERAL SCAN in .rdata')
for nm,vs,rv,rs,rp in secs:
 if nm!='.rdata':continue
 blob=d[rp:rp+rs]
 for m in re.finditer(rb'[\x20-\x7e]{3,}\x00',blob):
  s=m.group()[:-1]
  if any(k in s.lower() for k in [b'palu',b'0123456789abcdef',b'114514',b'success',b'failed',b'996',b'flag']):print('ASCII',hex(rv+m.start()),repr(s))
 for m in re.finditer(rb'(?:[\x20-\x7e]\x00){3,}\x00\x00',blob):
  try:s=m.group()[:-2].decode('utf-16le')
  except:continue
  if any(k in s.lower() for k in ['palu','0123456789abcdef','114514','success','failed','996','flag']):print('UTF16',hex(rv+m.start()),repr(s))
