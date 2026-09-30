from pathlib import Path
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP, X86_OP_IMM

path = Path(sys.argv[1])
data = path.read_bytes()
pe = struct.unpack_from("<I", data, 0x3C)[0]
num_sections = struct.unpack_from("<H", data, pe + 6)[0]
opt_size = struct.unpack_from("<H", data, pe + 20)[0]
opt = pe + 24
image_base = struct.unpack_from("<Q", data, opt + 24)[0]
section_table = opt + opt_size
sections = []
for i in range(num_sections):
    off = section_table + i * 40
    name = data[off:off+8].split(b"\0", 1)[0].decode("ascii", "replace")
    virtual_size, rva, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
    characteristics = struct.unpack_from("<I", data, off + 36)[0]
    sections.append((name, virtual_size, rva, raw_size, raw_ptr, characteristics))
    print(f"section={name!r} rva=0x{rva:x} vsize=0x{virtual_size:x} raw=0x{raw_ptr:x}+0x{raw_size:x} flags=0x{characteristics:x}")

def fileoff_to_va(fileoff):
    for name, vs, rva, rs, rp, ch in sections:
        if rp <= fileoff < rp + rs:
            return image_base + rva + (fileoff - rp)
    return None

target_ranges = [(fileoff_to_va(x), fileoff_to_va(x) + 0x80) for x in (0x4350,) if fileoff_to_va(x)]
print(f"image_base=0x{image_base:x} target_ranges={[(hex(a),hex(b)) for a,b in target_ranges]}")
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
for name, vs, rva, rs, rp, ch in sections:
    if not (ch & 0x20000000):
        continue
    code = data[rp:rp+rs]
    base = image_base + rva
    insns = list(md.disasm(code, base))
    xrefs = []
    for ix, ins in enumerate(insns):
        targets = []
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                targets.append(ins.address + ins.size + op.mem.disp)
            elif op.type == X86_OP_IMM:
                targets.append(op.imm)
        if any(a <= target < b for target in targets for a,b in target_ranges):
            xrefs.append(ix)
    print(f"--- xrefs in {name}, decoded={len(insns)} ---")
    seen = set()
    for ix in xrefs:
        lo, hi = max(0,ix-8), min(len(insns),ix+13)
        for j in range(lo,hi):
            if j in seen: continue
            ins=insns[j]
            print(f"0x{ins.address:x}: {ins.mnemonic:<8} {ins.op_str}")
            seen.add(j)
