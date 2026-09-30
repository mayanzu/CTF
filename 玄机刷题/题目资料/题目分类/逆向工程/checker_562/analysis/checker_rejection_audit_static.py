from pathlib import Path
import hashlib
import struct
import zipfile

root = Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\checker_562")
archives = [
    root / "checker_platform_20260929.zip",
    root / "originals" / "checker_platform_download_20260929_051349.zip",
    root.parent / "第一届启航杯checker_562" / "originals" / "checker.zip",
    root.parent / "原始下载附件" / "checker.zip",
]
extracted = root / "附件_20260929" / "checker.exe"

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()

member_blobs = []
zip_blobs = []
for archive in archives:
    raw = archive.read_bytes()
    zip_blobs.append(raw)
    with zipfile.ZipFile(archive) as zf:
        names = [n for n in zf.namelist() if not n.endswith("/")]
        if len(names) != 1:
            raise SystemExit(f"unexpected non-directory members: {archive}: {names}")
        member = zf.read(names[0])
    member_blobs.append(member)
    print("archive: " + str(archive).encode("unicode_escape").decode("ascii"))
    print(f"  bytes: {len(raw)}")
    print(f"  SHA-256: {sha256(raw)}")
    print(f"  member: {names[0]} ({len(member)} bytes)")
    print(f"  member SHA-256: {sha256(member)}")

if not all(blob == zip_blobs[0] for blob in zip_blobs[1:]):
    raise SystemExit("archive copies differ")
if not all(blob == member_blobs[0] for blob in member_blobs[1:]):
    raise SystemExit("ZIP member copies differ")
print("all four ZIP byte streams identical: True")
print("all four extracted checker.exe members identical: True")

exe = extracted.read_bytes()
print("extracted file: " + str(extracted).encode("unicode_escape").decode("ascii"))
print(f"extracted bytes: {len(exe)}")
print(f"extracted SHA-256: {sha256(exe)}")
print(f"matches ZIP member: {exe == member_blobs[0]}")
if exe != member_blobs[0]:
    raise SystemExit("extracted executable differs from ZIP member")

if exe[:2] != b"MZ":
    raise SystemExit("DOS MZ header not found")
pe = struct.unpack_from("<I", exe, 0x3C)[0]
if exe[pe:pe+4] != b"PE\0\0":
    raise SystemExit("PE header not found")
coff = pe + 4
section_count = struct.unpack_from("<H", exe, coff + 2)[0]
optional_size = struct.unpack_from("<H", exe, coff + 16)[0]
opt = coff + 20
if struct.unpack_from("<H", exe, opt)[0] != 0x10B:
    raise SystemExit("not PE32")
image_base = struct.unpack_from("<I", exe, opt + 28)[0]
sections = []
for i in range(section_count):
    off = opt + optional_size + 40 * i
    name = exe[off:off+8].split(b"\0", 1)[0].decode("ascii")
    vsize, rva, raw_size, raw_ptr = struct.unpack_from("<IIII", exe, off+8)
    sections.append((name, vsize, rva, raw_size, raw_ptr))

target_va = 0x404020
rva = target_va - image_base
matches = []
for name, vsize, sec_rva, raw_size, raw_ptr in sections:
    if sec_rva <= rva < sec_rva + max(vsize, raw_size):
        delta = rva - sec_rva
        if delta < raw_size:
            matches.append((name, raw_ptr + delta))
if len(matches) != 1:
    raise SystemExit(f"could not uniquely map target VA {target_va:#x}: {matches}")
section, file_off = matches[0]
end = exe.find(b"\0", file_off)
if end < 0:
    raise SystemExit("target string is not NUL terminated")
cipher = exe[file_off:end]
plain = bytes(b ^ 0x23 for b in cipher)
if bytes(b ^ 0x23 for b in plain) != cipher:
    raise SystemExit("XOR round-trip failed")
candidate = plain.decode("ascii")
print(f"PE image base: 0x{image_base:08X}")
print(f"target VA: 0x{target_va:08X}")
print(f"mapped section: {section}")
print(f"target file offset: 0x{file_off:X}")
print(f"cipher bytes: {len(cipher)}")
print(f"XOR-0x23 plaintext: {candidate}")
print(f"candidate ASCII length: {len(plain)}")
print(f"format flag{{[A-Za-z0-9_]+}}: {candidate.startswith('flag{') and candidate.endswith('}') and candidate[5:-1].isalnum()}")
print("XOR round-trip matches embedded cipher: True")

