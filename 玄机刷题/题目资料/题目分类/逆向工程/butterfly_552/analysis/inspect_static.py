from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_REG_RIP
P = Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\butterfly_552\analysis\extracted\butterfly")
data = P.read_bytes(); BASE=0x400000
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True

def disasm_at(addr,size):
    for ins in md.disasm(data[addr-BASE:addr-BASE+size],addr):
        print(f"{ins.address:#x}: {ins.bytes.hex():<24} {ins.mnemonic:<8} {ins.op_str}")

print("=== program entry ==="); disasm_at(0x401b70,0x40)
print("=== presumed main (entry passes 0x4018d0 as main) ==="); disasm_at(0x4018d0,0x600)
needles=[b"MMXEncode2024",b"Encoding file: %s",b"Successfully encoded to: %s",b"Encoded size: %zu bytes",b"Error: Cannot create file %s",b"Error: File write failed",b"Error: Cannot open file %s",b"Error: File read failed",b"Usage: %s <input_file> <output_file>",b"Example: %s plaintext.txt encoded.dat"]
targets={BASE+data.find(s):s.decode('ascii') for s in needles if data.find(s)>=0}
print("=== executable references to challenge strings ===")
for ins in md.disasm(data[0x1180:0x7f0a0], BASE+0x1180):
    refs=[]
    for op in ins.operands:
        if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
            va=ins.address+ins.size+op.mem.disp
            if va in targets: refs.append((va,targets[va]))
        elif op.type==X86_OP_IMM and op.imm in targets:
            refs.append((op.imm,targets[op.imm]))
    if refs:
        for va,s in refs: print(f"{ins.address:#x}: {ins.mnemonic} {ins.op_str} -> {va:#x} {s}")
