from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
P=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\第一届启航杯checker_562\analysis\extracted\checker.exe')
b=P.read_bytes(); base=0x400000; md=Cs(CS_ARCH_X86,CS_MODE_32)
for lo,hi,name in [(0x401150,0x401220,'startup helper'),(0x4012e0,0x401420,'entry/CRT and custom startup'),(0x401460,0x401530,'candidate helpers 401460..401530'),(0x401530,0x401800,'candidate challenge main/remainder')]:
 print(f'=== {name}: {lo:#x}-{hi:#x} ===')
 for i in md.disasm(b[lo-base:hi-base],lo): print(f'{i.address:#x}: {i.bytes.hex():<20} {i.mnemonic:<8} {i.op_str}')
print('=== data around challenge strings ===')
for off in [0x3200,0x3210,0x3220,0x3230,0x3240,0x3250,0x3270,0x3490]:
 print(f'{off:#x}:',b[off:off+64].hex(' '),repr(b[off:off+64]))
