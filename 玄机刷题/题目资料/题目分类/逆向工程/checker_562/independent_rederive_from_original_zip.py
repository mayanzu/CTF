from pathlib import Path
import hashlib
import re
import struct
import zipfile

root = Path(__file__).resolve().parent
archive = root / "originals" / "checker_platform_download_20260929_051349.zip"
mirror_paths = [root / "checker.exe"]


def sha256(blob):
    return hashlib.sha256(blob).hexdigest().upper()


def va_to_file_offset(blob, va):
    pe = struct.unpack_from("<I", blob, 0x3C)[0]
    coff = pe + 4
    section_count = struct.unpack_from("<H", blob, coff + 2)[0]
    optional_size = struct.unpack_from("<H", blob, coff + 16)[0]
    optional = coff + 20
    image_base = struct.unpack_from("<I", blob, optional + 28)[0]
    rva = va - image_base
    sections = []
    for index in range(section_count):
        section_offset = optional + optional_size + 40 * index
        name = blob[section_offset:section_offset + 8].split(b"\0", 1)[0].decode("ascii")
        virtual_size, section_rva, raw_size, raw_pointer = struct.unpack_from("<IIII", blob, section_offset + 8)
        if section_rva <= rva < section_rva + max(virtual_size, raw_size):
            delta = rva - section_rva
            if delta >= raw_size:
                raise ValueError(f"VA 0x{va:08X} is in an unbacked section tail")
            return raw_pointer + delta, name, image_base
    raise ValueError(f"VA 0x{va:08X} does not map to a PE section")


archive_bytes = archive.read_bytes()
print("original attachment copy: " + str(archive).encode("unicode_escape").decode("ascii"))
print(f"original ZIP size: {len(archive_bytes)}")
print(f"original ZIP SHA-256: {sha256(archive_bytes)}")
with zipfile.ZipFile(archive) as zf:
    members = [entry for entry in zf.infolist() if not entry.is_dir()]
    print(f"non-directory ZIP members: {[entry.filename for entry in members]}")
    if len(members) != 1:
        raise SystemExit("expected exactly one file in the original attachment ZIP")
    exe = zf.read(members[0])
print(f"ZIP member name: {members[0].filename}")
print(f"ZIP member size: {len(exe)}")
print(f"ZIP member SHA-256: {sha256(exe)}")
for path in mirror_paths:
    mirror = path.read_bytes()
    print("mirror: " + str(path.relative_to(root)).encode("unicode_escape").decode("ascii") + f"; size={len(mirror)}; SHA-256={sha256(mirror)}; byte-identical={mirror == exe}")
    if mirror != exe:
        raise SystemExit(f"mirror differs from the original ZIP member: {path}")
if exe[:2] != b"MZ":
    raise SystemExit("DOS MZ signature absent")
pe = struct.unpack_from("<I", exe, 0x3C)[0]
if exe[pe:pe + 4] != b"PE\0\0":
    raise SystemExit("PE signature absent")
coff = pe + 4
machine = struct.unpack_from("<H", exe, coff)[0]
optional = coff + 20
magic = struct.unpack_from("<H", exe, optional)[0]
image_base = struct.unpack_from("<I", exe, optional + 28)[0]
print(f"PE machine: 0x{machine:04X}; optional header: 0x{magic:04X}; image base: 0x{image_base:08X}")
if (machine, magic, image_base) != (0x014C, 0x010B, 0x00400000):
    raise SystemExit("unexpected PE architecture or image base")

# Read and assert the machine-code bytes that set the XOR key and perform the transform.
key_va = 0x00401496
key_offset, key_section, _ = va_to_file_offset(exe, key_va)
key_instruction = exe[key_offset:key_offset + 7]
if key_instruction[:3] != bytes.fromhex("C7 45 F0"):
    raise SystemExit("key-setting instruction is not the expected MOV immediate")
key = struct.unpack_from("<I", key_instruction, 3)[0]
xor_va = 0x004014BC
xor_offset, xor_section, _ = va_to_file_offset(exe, xor_va)
xor_instruction = exe[xor_offset:xor_offset + 4]
if xor_instruction != bytes.fromhex("31 CA 88 10"):
    raise SystemExit("input byte is not XORed and stored as expected")
loop_va = 0x004014D4
loop_offset, _, _ = va_to_file_offset(exe, loop_va)
loop_instruction = exe[loop_offset:loop_offset + 4]
if loop_instruction != bytes.fromhex("39 C2 77 CE"):
    raise SystemExit("unexpected loop bound / branch in transform")
print(f"XOR key immediate at 0x{key_va:08X} ({key_section}+0x{key_offset:X}): 0x{key:02X}")
print(f"transform bytes at 0x{xor_va:08X} ({xor_section}+0x{xor_offset:X}): {xor_instruction.hex(' ').upper()}")
print(f"loop compare/branch bytes at 0x{loop_va:08X}: {loop_instruction.hex(' ').upper()}")

# Verify checker passes that input through the transform and compares against VA 0x404020.
compare_va = 0x0040150D
compare_offset, compare_section, _ = va_to_file_offset(exe, compare_va)
compare_instruction = exe[compare_offset:compare_offset + 8]
if compare_instruction != bytes.fromhex("C7 44 24 04 20 40 40 00"):
    raise SystemExit("checker no longer points at the expected comparison target")
strcmp_call_va = 0x0040151B
call_offset, _, _ = va_to_file_offset(exe, strcmp_call_va)
call_bytes = exe[call_offset:call_offset + 5]
if call_bytes[0] != 0xE8:
    raise SystemExit("expected relative call after comparison target setup")
call_target = strcmp_call_va + 5 + struct.unpack_from("<i", call_bytes, 1)[0]
if call_target != 0x00403B70:
    raise SystemExit(f"unexpected comparison call target: 0x{call_target:08X}")
print(f"comparison target immediate at 0x{compare_va:08X}: VA 0x{struct.unpack_from('<I', compare_instruction, 4)[0]:08X}")
print(f"following call resolves to comparison routine: 0x{call_target:08X}")

# Verify main's input capacity and newline stripping from its actual instruction bytes.
fgets_va = 0x0040154D
fgets_offset, _, _ = va_to_file_offset(exe, fgets_va)
fgets_instruction = exe[fgets_offset:fgets_offset + 8]
if fgets_instruction != bytes.fromhex("C7 44 24 04 32 00 00 00"):
    raise SystemExit("unexpected fgets size argument")
newline_va = 0x004050A4
newline_offset, _, _ = va_to_file_offset(exe, newline_va)
if exe[newline_offset:newline_offset + 2] != b"\n\0":
    raise SystemExit("strcspn delimiter is not LF")
print(f"fgets size argument: {struct.unpack_from('<I', fgets_instruction, 4)[0]} bytes")
print(f"line terminator byte at 0x{newline_va:08X}: LF")

# Recover the complete NUL-terminated comparison value directly from the original ZIP member.
target_va = 0x00404020
target_offset, target_section, _ = va_to_file_offset(exe, target_va)
if target_section != ".data":
    raise SystemExit("comparison target is not in .data")
terminator = exe.find(b"\0", target_offset)
if terminator < 0:
    raise SystemExit("comparison string has no NUL terminator")
cipher = exe[target_offset:terminator]
plain = bytes(value ^ key for value in cipher)
if bytes(value ^ key for value in plain) != cipher:
    raise SystemExit("forward XOR verification failed")
if not re.fullmatch(rb"flag\{[A-Za-z0-9_]+\}", plain):
    raise SystemExit("derived bytes do not match the observed flag syntax")
if b"\0" in plain or b"\r" in plain or b"\n" in plain:
    raise SystemExit("derived input contains a forbidden line-input byte")
if len(plain) + 1 > 49:
    raise SystemExit("input plus LF would exceed fgets' maximum data length")
print(f"comparison target: VA 0x{target_va:08X} -> file offset 0x{target_offset:X} (.data)")
print(f"embedded comparison bytes before NUL: {len(cipher)}")
print(f"embedded comparison hex: {cipher.hex(' ').upper()}")
print(f"decoded input ASCII: {plain.decode('ascii')}")
print(f"derived input length: {len(plain)}; plus LF: {len(plain) + 1}; fgets limit: 49")
print(f"forward transform exactly matches embedded comparison: {bytes(value ^ key for value in plain) == cipher}")
print("STATIC_ONLY=true; no executable launched; no platform/network accessed; no submission made")

