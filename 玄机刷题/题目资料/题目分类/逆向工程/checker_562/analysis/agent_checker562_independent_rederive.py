from pathlib import Path
import hashlib
import re
import struct
import zipfile

root = Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\checker_562")
archive = root / "checker_platform_20260929.zip"
exe_path = root / "附件_20260929" / "checker.exe"
data = exe_path.read_bytes()
sha = hashlib.sha256(data).hexdigest().upper()
print(f"attachment path: {exe_path}")
print(f"attachment size: {len(data)}")
print(f"attachment SHA-256: {sha}")
with zipfile.ZipFile(archive) as zf:
    names = [n for n in zf.namelist() if not n.endswith("/")]
    print(f"ZIP members: {names}")
    assert len(names) == 1, "expected one non-directory ZIP member"
    zipped = zf.read(names[0])
    print(f"ZIP member size: {len(zipped)}")
    print(f"ZIP member SHA-256: {hashlib.sha256(zipped).hexdigest().upper()}")
    print(f"ZIP member equals extracted bytes: {zipped == data}")
    assert zipped == data

assert data[:2] == b"MZ"
pe = struct.unpack_from("<I", data, 0x3C)[0]
assert data[pe:pe+4] == b"PE\0\0"
coff = pe + 4
machine = struct.unpack_from("<H", data, coff)[0]
section_count = struct.unpack_from("<H", data, coff+2)[0]
opt_size = struct.unpack_from("<H", data, coff+16)[0]
opt = coff + 20
magic = struct.unpack_from("<H", data, opt)[0]
assert magic == 0x10B
image_base = struct.unpack_from("<I", data, opt+28)[0]
sections = []
for i in range(section_count):
    off = opt + opt_size + i*40
    name = data[off:off+8].split(b"\0",1)[0].decode("ascii")
    virtual_size, rva, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off+8)
    sections.append((name, virtual_size, rva, raw_size, raw_ptr))
print(f"PE machine: 0x{machine:04X}")
print(f"PE optional header magic: 0x{magic:04X}")
print(f"image base: 0x{image_base:08X}")
print("sections:")
for s in sections:
    print(f"  {s[0]} VA=0x{image_base+s[2]:08X} RVA=0x{s[2]:08X} raw=0x{s[4]:X} size=0x{s[3]:X}")

def va_to_raw(va):
    rva = va - image_base
    for name, vsize, srva, rawsize, rawptr in sections:
        if srva <= rva < srva + max(vsize, rawsize):
            delta = rva - srva
            if delta >= rawsize:
                raise ValueError(f"{va:#x} is in zero-filled section tail")
            return rawptr + delta, name
    raise ValueError(f"VA {va:#x} not mapped")

key_va = 0x401496
key_off, key_sec = va_to_raw(key_va)
key_instruction = data[key_off:key_off+7]
expected = bytes.fromhex("c7 45 f0 23 00 00 00")
print(f"key instruction VA: 0x{key_va:08X} section={key_sec} fileoff=0x{key_off:X}")
print(f"key instruction bytes: {key_instruction.hex(' ').upper()}")
assert key_instruction == expected, "instruction bytes differ from the audited disassembly"
key = struct.unpack_from("<I", key_instruction, 3)[0]
print(f"XOR key immediate: 0x{key:02X}")

target_va = 0x404020
target_off, target_sec = va_to_raw(target_va)
end = data.find(b"\0", target_off)
assert end >= 0
time_cipher = data[target_off:end]
plain = bytes(x ^ key for x in time_cipher)
reencoded = bytes(x ^ key for x in plain)
print(f"comparison target VA: 0x{target_va:08X} section={target_sec} fileoff=0x{target_off:X}")
print(f"cipher length: {len(time_cipher)}")
print(f"cipher hex: {time_cipher.hex(' ').upper()}")
print(f"decoded bytes hex: {plain.hex(' ').upper()}")
print(f"decoded ASCII: {plain.decode('ascii')}")
print(f"XOR round-trip exact: {reencoded == time_cipher}")
print(f"expected flag syntax: {bool(re.fullmatch(rb'flag\{[A-Za-z0-9_]+\}', plain))}")
assert machine == 0x14c
assert target_sec == ".data"
assert reencoded == time_cipher
assert re.fullmatch(rb"flag\{[A-Za-z0-9_]+\}", plain)
print(f"independently derived candidate: {plain.decode('ascii')}")
