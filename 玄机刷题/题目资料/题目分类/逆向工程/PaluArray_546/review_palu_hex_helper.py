from pathlib import Path
import struct,sys,hashlib
sys.stdout.reconfigure(encoding='utf-8',errors='backslashreplace')
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL
from capstone.x86 import X86_OP_IMM,X86_OP_MEM,X86_REG_RIP
p=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\PaluArray_546\PaluArray_flag_unpacked.exe');d=p.read_bytes()
pe=struct.unpack_from('<I',d,0x3c)[0];opt=pe+24;base=struct.unpack_from('<Q',d,opt+24)[0];n=struct.unpack_from('<H',d,pe+6)[0];st=opt+struct.unpack_from('<H',d,pe+20)[0];secs=[]
for j in range(n):
 q=st+j*40;nm=d[q:q+8].split(b'\0',1)[0].decode('ascii','replace');vs,rv,rs,rp=struct.unpack_from('<IIII',d,q+8);secs.append((nm,vs,rv,rs,rp))
def fo(r):
 for nm,vs,rv,rs,rp in secs:
  if rv<=r<rv+rs:return rp+r-rv
 return None
text=next(s for s in secs if s[0]=='.text');_,vs,rv,rs,rp=text;md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True;ins=list(md.disasm(d[rp:rp+rs],base+rv))
hex_rva=0x6318;hex_va=base+hex_rva
print('PE SHA256',hashlib.sha256(d).hexdigest(),'hex literal VA',hex(hex_va))
for i,op in [(i,o) for i in ins for o in i.operands if o.type==X86_OP_MEM and o.mem.base==X86_REG_RIP]:
 va=i.address+i.size+op.mem.disp
 if va==hex_va:
  print('HEX XREF',hex(i.address-base),i.mnemonic,i.op_str)
  lo=max(0,ins.index(i)-14);hi=min(len(ins),ins.index(i)+25)
  for q in ins[lo:hi]: print(f'{q.address-base:06x} {q.bytes.hex():<22} {q.mnemonic:<7} {q.op_str}')
print('\nCALL XREFS to helper RVA 0x14d8')
for idx,i in enumerate(ins):
 if i.group(CS_GRP_CALL) and i.operands and i.operands[0].type==X86_OP_IMM and i.operands[0].imm==base+0x14d8:
  print('caller',hex(i.address-base))
for a,b in [(0x14d8,0x1700),(0x1d8c,0x1dd8)]:
 print(f'\n=== RVA {a:#x}..{b:#x} ===')
 f=fo(a)
 for q in md.disasm(d[f:f+b-a],base+a):print(f'{q.address-base:06x} {q.bytes.hex():<22} {q.mnemonic:<7} {q.op_str}')
