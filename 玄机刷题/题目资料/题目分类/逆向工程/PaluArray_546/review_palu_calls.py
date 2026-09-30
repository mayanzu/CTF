from pathlib import Path
import struct, hashlib, collections
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL
from capstone.x86 import X86_OP_IMM
p=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluArray_546\PaluArray_flag_unpacked.exe')
d=p.read_bytes(); pe=struct.unpack_from('<I',d,0x3c)[0]; opt=pe+24
base=struct.unpack_from('<Q',d,opt+24)[0]; n=struct.unpack_from('<H',d,pe+6)[0]; os=struct.unpack_from('<H',d,pe+20)[0]; st=opt+os
secs=[]
for i in range(n):
 q=st+i*40; name=d[q:q+8].split(b'\0',1)[0].decode('ascii','replace'); vs,rv,rs,rp=struct.unpack_from('<IIII',d,q+8); secs.append((name,vs,rv,rs,rp))
def fo(rva):
 for name,vs,rv,rs,rp in secs:
  if rv<=rva<rv+rs:return rp+rva-rv
 raise ValueError(hex(rva))
text=next(s for s in secs if s[0]=='.text'); _,vs,rv,rs,rp=text
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
ins=list(md.disasm(d[rp:rp+rs],base+rv))
def line(i):
 return f'{i.address-base:06x}  {i.bytes.hex():<24} {i.mnemonic:<8} {i.op_str}'
print('PE SHA256',hashlib.sha256(d).hexdigest(),'text RVA',hex(rv),'rawsize',hex(rs),'instructions',len(ins))
for target in [0x1a48,0x1d70,0x1994,0x2118,0x2244,0x2404,0x2d70]:
 callers=[]
 for ix,i in enumerate(ins):
  if i.group(CS_GRP_CALL) and i.operands and i.operands[0].type==X86_OP_IMM and i.operands[0].imm==base+target:
   callers.append(ix)
 print('\nDIRECT CALLERS target RVA',hex(target),'count',len(callers))
 for ix in callers:
  lo=max(0,ix-28); hi=min(len(ins),ix+13)
  print('-- caller at',hex(ins[ix].address-base),'context --')
  for j in range(lo,hi): print(line(ins[j]))
print('\nFOCUSED RANGES')
for a,b in [(0x1980,0x1a48),(0x1d80,0x1f60),(0x1f50,0x2118),(0x2118,0x2244),(0x2244,0x2404)]:
 print('\n===',hex(a),'-',hex(b),'===')
 for i in ins:
  r=i.address-base
  if a<=r<b: print(line(i))
