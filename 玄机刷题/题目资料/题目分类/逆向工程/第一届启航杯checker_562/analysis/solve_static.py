from pathlib import Path
from zipfile import ZipFile
import hashlib
import struct

ROOT = Path(__file__).resolve().parent.parent
ARCHIVE = ROOT / "originals" / "checker.zip"
EXE = ROOT / "analysis" / "extracted" / "checker.exe"
IMAGE_BASE_EXPECTED = 0x400000
ENCRYPTED_VA = 0x404020
KEY = 0x23

archive_bytes = ARCHIVE.read_bytes()
binary = EXE.read_bytes()
print("=== 静态附件完整性 ===")
print("ZIP SHA256:", hashlib.sha256(archive_bytes).hexdigest().upper())
print("EXE SHA256:", hashlib.sha256(binary).hexdigest().upper())
print("EXE length:", len(binary))
with ZipFile(ARCHIVE) as zf:
    names = zf.namelist()
    print("ZIP entries:", names)
    print("ZIP test result:", zf.testzip())
    assert names == ["checker.exe"], "归档条目与预期不符"
    archived = zf.read("checker.exe")
    assert archived == binary, "解压文件和归档内容不一致"
print("archive bytes equal extracted file: True")

print("\n=== 读取 PE 节表并映射加密数据 ===")
peoff = struct.unpack_from("<I", binary, 0x3C)[0]
assert binary[peoff:peoff + 4] == b"PE\0\0"
machine, nsects, timestamp, symptr, nsyms, optsize, chars = struct.unpack_from("<HHIIIHH", binary, peoff + 4)
opt = peoff + 24
magic = struct.unpack_from("<H", binary, opt)[0]
assert magic == 0x10B, f"Expected PE32 optional header, got {magic:#x}"
image_base = struct.unpack_from("<I", binary, opt + 28)[0]
entry_rva = struct.unpack_from("<I", binary, opt + 16)[0]
print(f"machine={machine:#06x}, sections={nsects}, PE32 image_base={image_base:#x}, entry={image_base + entry_rva:#x}")
assert image_base == IMAGE_BASE_EXPECTED

sections = []
sectab = opt + optsize
for i in range(nsects):
    p = sectab + i * 40
    name = binary[p:p + 8].split(b"\0", 1)[0].decode("ascii")
    virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from("<IIII", binary, p + 8)
    sections.append((name, virtual_address, virtual_size, raw_ptr, raw_size))
    print(f"{name}: RVA={virtual_address:#x}, virtual_size={virtual_size:#x}, raw={raw_ptr:#x}+{raw_size:#x}")

target_rva = ENCRYPTED_VA - image_base
matches = [s for s in sections if s[0] == ".data"]
assert len(matches) == 1
name, section_rva, virtual_size, raw_ptr, raw_size = matches[0]
assert section_rva <= target_rva < section_rva + max(virtual_size, raw_size)
raw_offset = raw_ptr + (target_rva - section_rva)
end = binary.index(b"\0", raw_offset)
ciphertext = binary[raw_offset:end]
print(f"encrypted_flag VA={ENCRYPTED_VA:#x}, RVA={target_rva:#x}, raw offset={raw_offset:#x}")
print("encrypted bytes:", ciphertext.hex())
print("encrypted length before NUL:", len(ciphertext))

print("\n=== 根据反汇编的逐字节 XOR 逻辑还原 ===")
candidate = bytes(value ^ KEY for value in ciphertext)
decoded = candidate.decode("ascii", "strict")
print(f"key={KEY:#04x}; candidate bytes={candidate!r}")
print("candidate:", decoded)
print("candidate length:", len(candidate))
print("format check:", candidate.startswith(b"flag{") and candidate.endswith(b"}"))
forward = bytes(value ^ KEY for value in candidate)
print("forward XOR:", forward.hex())
print("complete ciphertext equality:", forward == ciphertext)
assert candidate.startswith(b"flag{") and candidate.endswith(b"}")
assert forward == ciphertext
print("RESULT: static reconstruction and exact forward re-encryption both passed.")
