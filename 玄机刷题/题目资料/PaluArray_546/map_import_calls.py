from pathlib import Path
import struct,sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_MEM,X86_REG_RIP
p=Path(sys.argv[1]);d=p.read_bytes();pe=struct.unpack_from('<I',d,0x3c)[0]; opt=pe+24;base=struct.unpack_from('<Q',d,opt+24)[0]; n=struct.unpack_from('<H',d,pe+6)[0]; os=struct.unpack_from('<H',d,pe+20)[0]; st=opt+os; sections=[]
for i in range(n):
 q=st+i*40;name=d[q:q+8].split(b'\0',1)[0].decode('ascii','replace');vs,rv,rs,rp=struct.unpack_from('<IIII',d,q+8);sections.append((name,rv,rs,rp))
def fo(rva):
 for name,rv,rs,rp in sections:
  if rv<=rva<rv+rs:return rp+rva-rv
 raise ValueError(hex(rva))
nd=struct.unpack_from('<I',d,opt+108)[0]; imp_rva,imp_size=struct.unpack_from('<II',d,opt+112+8)
imports={}
if imp_rva:
 pos=fo(imp_rva)
 while True:
  oft,ts,fc,nr,ft=struct.unpack_from('<IIIII',d,pos)
  if not (oft|nr|ft):break
  dll=d[fo(nr):].split(b'\0',1)[0].decode('ascii','replace'); thunk=oft or ft; j=0
  while True:
   v=struct.unpack_from('<Q',d,fo(thunk)+j*8)[0]
   if not v:break
   if v>>63:name=f'ordinal_{v&0xffff}'
   else:name=d[fo(v)+2:].split(b'\0',1)[0].decode('ascii','replace')
   imports[base+ft+j*8]=dll+'!'+name;j+=1
  pos+=20
print('--- IAT ---')
for va,name in sorted(imports.items()):print(f'{va:#x} {name}')
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
print('--- calls into IAT in selected functions ---')
for start,end in [(0x1040,0x1080),(0x1994,0x1a47),(0x1a48,0x1d92),(0x1dd8,0x1f4e),(0x1f6c,0x20b4),(0x2118,0x2404)]:
 print(f'[{start:#x},{end:#x})')
 for ins in md.disasm(d[fo(start):fo(end-1)+1],base+start):
  for o in ins.operands:
   if o.type==X86_OP_MEM and o.mem.base==X86_REG_RIP:
    va=ins.address+ins.size+o.mem.disp
    if va in imports:print(f'{ins.address:#x}: {ins.mnemonic} {ins.op_str} => {imports[va]}')

