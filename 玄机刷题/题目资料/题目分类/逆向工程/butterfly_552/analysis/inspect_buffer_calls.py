from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
p=Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\butterfly_552\analysis\extracted\butterfly")
b=p.read_bytes(); base=0x400000; md=Cs(CS_ARCH_X86,CS_MODE_64)
def show(a,n):
 print(f'--- {a:#x} ---')
 for i in md.disasm(b[a-base:a-base+n],a): print(f'{i.address:#x}: {i.bytes.hex():<24} {i.mnemonic:<8} {i.op_str}')
show(0x412620,0x180)
show(0x41cc80,0x300)
