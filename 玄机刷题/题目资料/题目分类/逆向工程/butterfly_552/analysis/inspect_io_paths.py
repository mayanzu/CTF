from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
p=Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\butterfly_552\analysis\extracted\butterfly")
b=p.read_bytes(); base=0x400000; md=Cs(CS_ARCH_X86,CS_MODE_64)
def show(start,end):
    print(f"--- {start:#x}..{end:#x} ---")
    for i in md.disasm(b[start-base:end-base],start):
        print(f"{i.address:#x}: {i.bytes.hex():<24} {i.mnemonic:<8} {i.op_str}")
show(0x401a7d,0x401ac5)
show(0x401ca0,0x401d24)
