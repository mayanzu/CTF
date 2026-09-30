from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

p=Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\PaluFlat_547\analysis\PaluFlat_head_0x5000.bin")
b=p.read_bytes()
text=b[0x400:0x2e00]
table=b[0x3000:0x30b8]
base=0x405000
md=Cs(CS_ARCH_X86,CS_MODE_64)
targets=[]
for i in range(46):
    rel=struct.unpack_from("<i",table,i*4)[0]
    targets.append(base+rel)
out=[]
for i,addr in enumerate(targets):
    out.append(f"===== STATE {i:02d} -> {addr:#x} =====")
    off=addr-0x401000
    n=0
    for ins in md.disasm(text[off:],addr):
        out.append(f"{ins.address:#x}: {ins.bytes.hex():<24} {ins.mnemonic:<8} {ins.op_str}")
        n+=1
        if ins.mnemonic in ("jmp","ret","retq","ud2") or n>=80:
            break
Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\PaluFlat_547\analysis\vm_cases.txt").write_text("\n".join(out),encoding="utf-8")
print("jump table count:",len(targets))
print("jump table targets:")
for i,t in enumerate(targets): print(f"{i:02d}: {t:#x}")
print("case dump lines:",len(out))
print("case dump path: analysis/vm_cases.txt")
