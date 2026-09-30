from pathlib import Path
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

path = Path(sys.argv[1])
data = path.read_bytes()
pe = struct.unpack_from("<I", data, 0x3C)[0]
opt = pe + 24
entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
image_base = struct.unpack_from("<Q", data, opt + 24)[0]
num_sections = struct.unpack_from("<H", data, pe + 6)[0]
opt_size = struct.unpack_from("<H", data, pe + 20)[0]
section_table = opt + opt_size
print(f"entry_rva=0x{entry_rva:x} entry_va=0x{image_base+entry_rva:x}")
for i in range(num_sections):
    off = section_table + i*40
    name = data[off:off+8].split(b"\0",1)[0].decode("ascii","replace")
    vsize, rva, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off+8)
    if rva <= entry_rva < rva + max(vsize,raw_size) and raw_size:
        fileoff = raw_ptr + entry_rva-rva
        print(f"entry_section={name} file_offset=0x{fileoff:x}")
        md=Cs(CS_ARCH_X86,CS_MODE_64)
        for n, ins in enumerate(md.disasm(data[fileoff:fileoff+0x800], image_base+entry_rva)):
            if n >= 120: break
            print(f"0x{ins.address:x}: {ins.mnemonic:<8} {ins.op_str}")
