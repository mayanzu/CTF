from pathlib import Path
import struct,sys,hashlib
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_MEM,X86_REG_RIP,X86_OP_IMM
sys.stdout.reconfigure(encoding='utf-8',errors='backslashreplace')
p=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\PaluArray_546\PaluArray_flag_unpacked.exe');d=p.read_bytes()
pe=struct.unpack_from('<I',d,0x3c)[0];opt=pe+24;base=struct.unpack_from('<Q',d,opt+24)[0];entry=struct.unpack_from('<I',d,opt+16)[0];ns=struct.unpack_from('<H',d,pe+6)[0];os=struct.unpack_from('<H',d,pe+20)[0];st=opt+os
sections=[]
for i in range(ns):
 q=st+i*40;name=d[q:q+8].split(b'\0',1)[0].decode('ascii','replace');vs,rv,rs,rp=struct.unpack_from('<IIII',d,q+8);flags=struct.unpack_from('<I',d,q+36)[0];sections.append((name,vs,rv,rs,rp,flags))
def fo_va(va):
 r=va-base
 for name,vs,rv,rs,rp,flags in sections:
  if rv<=r<rv+rs:return rp+r-rv
 return None
def fo_rva(rva):return fo_va(base+rva)
print('FILE',p,'BYTES',len(d),'SHA256',hashlib.sha256(d).hexdigest(),'IMAGE_BASE',hex(base),'ENTRY_RVA',hex(entry),'ENTRY_VA',hex(base+entry))
print('SECTIONS',[(n,hex(rv),hex(rs),hex(rp),hex(fl)) for n,vs,rv,rs,rp,fl in sections])
# Read PE import table, used only to annotate calls; this does not load or execute the PE.
nd=struct.unpack_from('<I',d,opt+108)[0];imp_rva,imp_size=struct.unpack_from('<II',d,opt+112+8);imports={}
if imp_rva:
 pos=fo_rva(imp_rva)
 while True:
  oft,ts,fc,nr,ft=struct.unpack_from('<IIIII',d,pos)
  if not (oft|nr|ft):break
  dll=d[fo_rva(nr):].split(b'\0',1)[0].decode('ascii','replace');thunk=oft or ft;j=0
  while True:
   v=struct.unpack_from('<Q',d,fo_rva(thunk)+8*j)[0]
   if not v:break
   if v>>63:name=f'ordinal_{v&0xffff}'
   else:name=d[fo_rva(v)+2:].split(b'\0',1)[0].decode('ascii','replace')
   imports[base+ft+8*j]=dll+'!'+name;j+=1
  pos+=20
print('IMPORTS',len(imports))
for va,name in sorted(imports.items()):
 if any(x in name.lower() for x in ['md5','hash','printf','string','write','format','cin','cout','puts','itoa','sprintf','tostring']):print('IMPORT',hex(va),name)
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
ranges=[(0x1700,0x1a48),(0x1a48,0x1d96),(0x1d80,0x1f60),(0x1f50,0x2118),(0x2118,0x2244),(0x2244,0x2404),(0x2410,0x26a0),(0x2d70,0x2f50)]
for a,b in ranges:
 f=fo_rva(a)
 if f is None:print('UNMAPPED',hex(a),hex(b));continue
 print(f'\n===== DISASSEMBLY RVA {a:#x}..{b:#x} VA {base+a:#x} =====')
 for ins in md.disasm(d[f:f+(b-a)],base+a):
  refs=[]
  for op in ins.operands:
   if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
    va=ins.address+ins.size+op.mem.disp
    if va in imports:refs.append('IAT='+imports[va])
    off=fo_va(va)
    if off is not None:
     raw=d[off:off+40]
     if raw[:2]==b'\xff\xfe' or len(raw)>=2:
      ss=raw.decode('utf-16le',errors='ignore').split('\0',1)[0]
      if ss and sum(ch.isprintable() for ch in ss[:20])>=min(4,len(ss[:20])):refs.append('UTF16='+repr(ss[:30]))
     aa=raw.split(b'\0',1)[0]
     if len(aa)>=4 and all(32<=x<127 for x in aa[:min(len(aa),20)]):refs.append('ASCII='+repr(aa[:30].decode('ascii','replace')))
   elif op.type==X86_OP_IMM and ins.mnemonic.startswith('call'):
    refs.append('CALL_TARGET='+hex(op.imm))
  print(f'{ins.address:#x}: {ins.mnemonic:<8} {ins.op_str} {" ".join(refs)}')
