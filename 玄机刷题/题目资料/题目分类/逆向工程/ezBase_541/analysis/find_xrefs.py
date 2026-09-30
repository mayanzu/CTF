"""Find instructions in unpacked x64 bytes that reference a target VA."""
from pathlib import Path
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM
from capstone.x86 import X86_REG_RIP

p = Path(sys.argv[1])
target = int(sys.argv[2], 0)
buf = p.read_bytes()
imagebase = 0x140000000
start_rva = 0x1000
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
hits = []
for off in range(max(0, len(buf) - 15)):
    insns = list(md.disasm(buf[off:off+15], imagebase + start_rva + off, count=1))
    if not insns:
        continue
    ins = insns[0]
    for op in ins.operands:
        if op.type == CS_OP_MEM and op.mem.base == X86_REG_RIP:
            ea = ins.address + ins.size + op.mem.disp
            if ea == target:
                hits.append((off, ins, ea))
for off, ins, ea in hits:
    print(f"offset=0x{off:x} VA=0x{ins.address:x} bytes={ins.bytes.hex(' ')} {ins.mnemonic} {ins.op_str} => 0x{ea:x}")
print(f"hits={len(hits)} target=0x{target:x}")
