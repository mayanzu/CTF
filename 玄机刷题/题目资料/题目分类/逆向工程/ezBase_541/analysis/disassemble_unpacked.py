"""Disassemble statically reconstructed image bytes; never executes the target."""
from pathlib import Path
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

p = Path(sys.argv[1])
offset = int(sys.argv[2], 0)
size = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x400
base = 0x140001000 + offset
data = p.read_bytes()[offset:offset+size]
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
for i, ins in enumerate(md.disasm(data, base)):
    print(f"{i:04d} {ins.address:016x}: {ins.bytes.hex(' '):<40} {ins.mnemonic:<8} {ins.op_str}")
