from pathlib import Path
import struct

exe = Path(__file__).parent / "extracted" / "checker.exe"
data = exe.read_bytes()
assert data[:2] == b"MZ", "missing DOS header"
pe = struct.unpack_from("<I", data, 0x3C)[0]
assert data[pe:pe+4] == b"PE\0\0", "missing PE signature"
machine, nsections, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, pe + 4)
assert machine == 0x14C, f"expected i386, got 0x{machine:04x}"
opt = pe + 24
magic = struct.unpack_from("<H", data, opt)[0]
assert magic == 0x10B, f"expected PE32, got 0x{magic:04x}"
image_base = struct.unpack_from("<I", data, opt + 28)[0]
section_table = opt + opt_size
rva = 0x404020 - image_base
sections = []
for i in range(nsections):
    off = section_table + 40 * i
    name = data[off:off+8].split(b"\0", 1)[0].decode("ascii", "replace")
    vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
    sections.append((name, va, vsize, raw_ptr, raw_size))
    span = max(vsize, raw_size)
    if va <= rva < va + span:
        file_offset = raw_ptr + (rva - va)
        break
else:
    raise AssertionError(f"target RVA 0x{rva:x} not in any section")
assert file_offset == 0x3220, f"unexpected mapping: 0x{file_offset:x}"
end = data.index(b"\0", file_offset)
cipher = data[file_offset:end]
plain = bytes(b ^ 0x23 for b in cipher)
candidate = plain.decode("ascii")
forward = bytes(ch ^ 0x23 for ch in plain)
print(f"FILE={exe}")
print(f"PE_MACHINE=0x{machine:04X} PE_MAGIC=0x{magic:03X} IMAGE_BASE=0x{image_base:08X}")
print("SECTIONS=" + repr(sections))
print(f"TARGET_VA=0x404020 TARGET_RVA=0x{rva:04X} FILE_OFFSET=0x{file_offset:04X}")
print(f"TARGET_HEX={cipher.hex(' ').upper()}")
print(f"TARGET_LENGTH={len(cipher)}")
print(f"DECODED={candidate}")
print(f"FLAG_SHAPE={candidate.startswith('flag{') and candidate.endswith('}')}")
print(f"FORWARD_XOR_EXACT={forward == cipher}")
assert len(cipher) == 43
assert candidate.startswith("flag{") and candidate.endswith("}")
assert forward == cipher
print("RESULT=PASS; checker.exe was parsed as data and never executed")
