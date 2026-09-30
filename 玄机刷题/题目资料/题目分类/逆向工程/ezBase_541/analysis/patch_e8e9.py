"""Reproduce UPX's statically observed E8/E9 and near-Jcc filter on output."""
from pathlib import Path
import sys

source = Path(sys.argv[1])
target = Path(sys.argv[2])
buf = bytearray(source.read_bytes())
scan_end = min(0x2A00 - 3, len(buf))
base_low32 = 0x40001000  # ImageBase 0x140000000 + output start RVA 0x1000.
patched = []
i = 0
while i < scan_end:
    op = buf[i]
    near_jcc = 0x80 <= op <= 0x8F and i > 0 and buf[i - 1] == 0x0F
    if op in (0xE8, 0xE9) or near_jcc:
        operand = i + 1
        if operand + 4 > len(buf):
            break
        # The loader uses `sub al, dl` with DL=0 as the filter condition.
        if buf[operand] == 0:
            encoded = int.from_bytes(buf[operand:operand+4], "little")
            bswap = int.from_bytes(buf[operand:operand+4], "big")
            edi = (base_low32 + operand) & 0xFFFFFFFF
            value = (bswap - edi + base_low32) & 0xFFFFFFFF
            buf[operand:operand+4] = value.to_bytes(4, "little")
            patched.append((i, operand, encoded, value))
        # lodsd advances RSI by four; on either branch the scan resumes there.
        i = operand + 4
    else:
        i += 1

target.parent.mkdir(parents=True, exist_ok=True)
target.write_bytes(buf)
print(f"scan_end=0x{scan_end:x} patched_operands={len(patched)}")
for op_off, imm_off, old, new in patched[:32]:
    print(f"opcode@0x{op_off:x} operand@0x{imm_off:x} old={old:08x} new={new:08x}")
print(f"output_path={target}")
