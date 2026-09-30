from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
P=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\第一届启航杯checker_562\analysis\extracted\checker.exe')
b=P.read_bytes(); base=0x400000; md=Cs(CS_ARCH_X86,CS_MODE_32)
insns=list(md.disasm(b[0x400:0x400+11776],base+0x1000))
for lo,hi in [(0x4014e0,0x401610),(0x401b00,0x401c00)]:
 print(f'=== aligned .text instructions {lo:#x}-{hi:#x} ===')
 for i in insns:
  if lo<=i.address<hi: print(f'{i.address:#x}: {i.bytes.hex():<20} {i.mnemonic:<8} {i.op_str}')
