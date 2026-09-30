from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
P=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\butterfly_552\analysis\extracted\butterfly')
b=P.read_bytes(); base=0x400000; md=Cs(CS_ARCH_X86,CS_MODE_64)
for lo,hi,name in [(0x4018d0,0x401b70,'main: argc/input/read/loop/write call setup'),(0x401ca0,0x401d24,'write helper')]:
 print(f'=== {name} [{lo:#x},{hi:#x}) ===')
 for i in md.disasm(b[lo-base:hi-base],lo):
  print(f'{i.address:#x}: {i.bytes.hex():<24} {i.mnemonic:<8} {i.op_str}')
