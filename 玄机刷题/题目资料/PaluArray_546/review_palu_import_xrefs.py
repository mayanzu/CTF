from pathlib import Path
import struct,hashlib
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_MEM,X86_REG_RIP
p=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluArray_546\PaluArray_flag_unpacked.exe'); d=p.read_bytes()
pe=struct.unpack_from('<I',d,0x3c)[0]; opt=pe+24; base=struct.unpack_from('<Q',d,opt+24)[0]; n=struct.unpack_from('<H',d,pe+6)[0]; st=opt+struct.unpack_from('<H',d,pe+20)[0]; secs=[]
for j in range(n):
 q=st+j*40; nm=d[q:q+8].split(b'\0',1)[0].decode('ascii','replace'); vs,rv,rs,rp=struct.unpack_from('<IIII',d,q+8); secs.append((nm,vs,rv,rs,rp))
def fo(rva):
 for nm,vs,rv,rs,rp in secs:
  if rv<=rva<rv+rs:return rp+rva-rv
 raise ValueError(hex(rva))
def fo_va(va): return fo(va-base)
imp_rva=struct.unpack_from('<I',d,opt+112+8)[0]; imports={}
if imp_rva:
 pos=fo(imp_rva)
 while True:
  oft,ts,fc,nr,ft=struct.unpack_from('<IIIII',d,pos)
  if not (oft|nr|ft):break
  dll=d[fo(nr):].split(b'\0',1)[0].decode('ascii','replace'); thunk=oft or ft; k=0
  while True:
   v=struct.unpack_from('<Q',d,fo(thunk)+8*k)[0]
   if not v:break
   name=('ordinal_'+str(v&0xffff)) if v>>63 else d[fo(v)+2:].split(b'\0',1)[0].decode('ascii','replace')
   imports[base+ft+8*k]=dll+'!'+name;k+=1
  pos+=20
print('PE SHA256',hashlib.sha256(d).hexdigest(),'imports',len(imports))
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
text=next(s for s in secs if s[0]=='.text'); _,vs,rv,rs,rp=text; allins=list(md.disasm(d[rp:rp+rs],base+rv))
for a,b in [(0x1e00,0x1f20),(0x1f6c,0x1fb8),(0x1fb8,0x20b4),(0x1994,0x1a48),(0x1a48,0x1c40)]:
 print('\n=== RVA',hex(a),'-',hex(b),'===')
 for ins in allins:
  r=ins.address-base
  if not a<=r<b:continue
  extra=[]
  for op in ins.operands:
   if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
    va=ins.address+ins.size+op.mem.disp
    if va in imports: extra.append('IAT '+hex(va)+' '+imports[va])
    off=fo_va(va)
    if off is not None:
     raw=d[off:off+48]
     asc=raw.split(b'\0',1)[0]
     if asc and all(32<=c<127 for c in asc[:24]): extra.append('ASCII '+repr(asc[:48]))
     wide=raw.decode('utf-16le','ignore').split('\0',1)[0]
     if wide and sum(c.isprintable() for c in wide[:20])>=max(4,len(wide[:20])//2):extra.append('UTF16 '+repr(wide[:40]))
  print(f'{r:06x} {ins.bytes.hex():<22} {ins.mnemonic:<7} {ins.op_str}',(' ; '+' | '.join(extra) if extra else ''))
print('\nIMPORTS FROM RELEVANT CALLED IAT CELLS')
needed=set()
for ins in allins:
 r=ins.address-base
 if 0x1e00<=r<0x20b4 or 0x1994<=r<0x1a48:
  for op in ins.operands:
   if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
    va=ins.address+ins.size+op.mem.disp
    if va in imports: needed.add(va)
for va in sorted(needed):print(hex(va),imports[va])
