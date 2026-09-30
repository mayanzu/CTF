"""Decode the compact UPX import table to identify each indirect-call IAT slot."""
from pathlib import Path
import struct

root = Path(__file__).parent.parent
exe = (root / "ezBase" / "ezre.exe").read_bytes()
image = (Path(__file__).parent / "upx0_patched.bin").read_bytes()

def rva_to_file(rva):
    if 0xE000 <= rva < 0xE400:
        return 0x2000 + (rva - 0xE000)
    raise ValueError(f"RVA 0x{rva:x} outside known raw-backed .rsrc span")

def cstr(buf, off):
    end = buf.index(0, off)
    return buf[off:end].decode("ascii", "replace")

desc = 0xB000
for module_index in range(16):
    dll_rel, iat_rel = struct.unpack_from("<II", image, desc)
    if dll_rel == 0 and iat_rel == 0:
        print(f"table_end_offset=0x{desc:x}")
        break
    dll_rva = 0xE1A0 + dll_rel
    dll = cstr(exe, rva_to_file(dll_rva))
    print(f"module[{module_index}] name={dll} dll_rva=0x{dll_rva:x} first_iat_rva=0x{0x1000+iat_rel:x} descriptor_offset=0x{desc:x}")
    pos = desc + 8
    slot_rva = 0x1000 + iat_rel
    count = 0
    while pos < len(image) and image[pos] != 0:
        marker = image[pos]
        pos += 1
        if marker > 0xEF:
            ordinal = ((marker & 0x0F) << 16) | struct.unpack_from("<H", image, pos)[0]
            pos += 2
            print(f"  IAT RVA=0x{slot_rva:x} ordinal=#{ordinal}")
        else:
            name = cstr(image, pos)
            print(f"  IAT RVA=0x{slot_rva:x} marker={marker} name={name}")
            pos += len(name) + 1
        slot_rva += 8
        count += 1
    print(f"  symbols={count} terminator_offset=0x{pos:x}")
    desc = pos + 1
else:
    print("table_end_not_found")
