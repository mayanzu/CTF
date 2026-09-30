from pathlib import Path
import struct
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from capstone.x86 import X86_OP_IMM,X86_OP_MEM
P=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\第一届启航杯checker_562\analysis\extracted\checker.exe')
b=P.read_bytes(); base=0x400000; md=Cs(CS_ARCH_X86,CS_MODE_32); md.detail=True
# Known VAs from PE section mapping / literal scan.
targets={0x404020:'encrypted bytes/table at file offset 0x3220',0x405093:'Enter the flag',0x4050a6:'Correct message',0x4050c2:'Incorrect message'}
text=b[0x400:0x400+11776]; va=base+0x1000
insns=list(md.disasm(text,va))
print('disassembled .text instructions:',len(insns))
for ins in insns:
 refs=[]
 for op in ins.operands:
  if op.type==X86_OP_IMM and op.imm in targets: refs.append(targets[op.imm])
  elif op.type==X86_OP_MEM and op.mem.disp:
   # absolute disp in 32-bit mode
   d=op.mem.disp & 0xffffffff
   if d in targets: refs.append(targets[d])
 if refs: print(f'XREF {ins.address:#x}: {ins.mnemonic} {ins.op_str} => {refs}')
print('=== direct relative call graph targets in challenge-text address range ===')
for ins in insns:
 if ins.mnemonic=='call' and ins.operands and ins.operands[0].type==X86_OP_IMM:
  t=ins.operands[0].imm
  if 0x401000<=t<0x403d00:
   print(f'{ins.address:#x} -> {t:#x}')
