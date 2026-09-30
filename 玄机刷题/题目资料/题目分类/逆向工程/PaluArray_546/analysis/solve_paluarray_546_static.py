from __future__ import annotations

import hashlib
import struct
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "originals" / "PaluArray_flag.zip"
EXTRACTED = ROOT / "extracted" / "PaluArray_flag.exe"
PACKED = ROOT / "PaluArray_flag.exe"
PATCHED = ROOT / "PaluArray_flag_upx_names.exe"
UNPACKED = ROOT / "analysis" / "PaluArray_flag_unpacked_repro.exe"
KNOWN_UNPACKED = ROOT / "PaluArray_flag_unpacked.exe"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def parse_pe(data: bytes):
    if data[:2] != b"MZ":
        raise ValueError("missing DOS MZ signature")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic != 0x20B:
        raise ValueError(f"expected PE32+, got optional-header magic {magic:#x}")
    entry_rva = struct.unpack_from("<I", data, optional + 16)[0]
    image_base = struct.unpack_from("<Q", data, optional + 24)[0]
    section_table = optional + optional_size
    sections = []
    for i in range(section_count):
        off = section_table + i * 40
        name = data[off:off + 8].split(b"\0", 1)[0].decode("ascii", "strict")
        virtual_size, rva, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append((name, virtual_size, rva, raw_size, raw_ptr))
    return entry_rva, image_base, sections


def rva_to_offset(rva: int, sections) -> int:
    for name, _virtual_size, section_rva, raw_size, raw_ptr in sections:
        if section_rva <= rva < section_rva + raw_size:
            return raw_ptr + rva - section_rva
    raise ValueError(f"RVA {rva:#x} is not backed by section raw data")


def read_utf16z(data: bytes, rva: int, sections) -> str:
    off = rva_to_offset(rva, sections)
    end = off
    while end + 1 < len(data):
        if data[end:end + 2] == b"\0\0":
            return data[off:end].decode("utf-16le", "strict")
        end += 2
    raise ValueError(f"unterminated UTF-16 string at RVA {rva:#x}")


def main() -> None:
    with zipfile.ZipFile(ARCHIVE) as zf:
        names = zf.namelist()
        if names != ["PaluArray_flag.exe"]:
            raise ValueError(f"unexpected archive members: {names!r}")
        archive_bytes = zf.read(names[0])
    extracted_bytes = EXTRACTED.read_bytes()
    packed_bytes = PACKED.read_bytes()
    patched_bytes = PATCHED.read_bytes()
    unpacked_bytes = UNPACKED.read_bytes()
    known_unpacked_bytes = KNOWN_UNPACKED.read_bytes()

    if archive_bytes != extracted_bytes or extracted_bytes != packed_bytes:
        raise ValueError("ZIP member, extracted file, and project input differ")
    expected_patched = bytearray(packed_bytes)
    for offset, before, after in (
        (0x208, b"PALU", b"UPX0"),
        (0x230, b"PALU", b"UPX1"),
        (0x3E0, b"PALU", b"UPX!"),
    ):
        if bytes(expected_patched[offset:offset + 4]) != before:
            raise ValueError(f"unexpected original bytes at file offset {offset:#x}")
        expected_patched[offset:offset + 4] = after
    if bytes(expected_patched) != patched_bytes:
        raise ValueError("patched file differs from the three documented UPX marker edits")
    if unpacked_bytes != known_unpacked_bytes:
        raise ValueError("reproduced UPX unpacking differs from saved unpacked copy")

    entry_rva, image_base, sections = parse_pe(unpacked_bytes)
    # Static initialization at RVA 0x1040 passes this pointer to the table.
    # RVA 0x5e66 is the final ASCII 'g' in "string too long\\0"; reading
    # UTF-16LE there would incorrectly prepend that byte to the real alphabet.
    alphabet_rva = 0x5E68
    alphabet = read_utf16z(unpacked_bytes, alphabet_rva, sections)
    target = read_utf16z(unpacked_bytes, 0x5EA0, sections)
    prefix = read_utf16z(unpacked_bytes, 0x5E90, sections)
    suffix = read_utf16z(unpacked_bytes, 0x5E8C, sections)
    dialog_title = read_utf16z(unpacked_bytes, 0x5E80, sections)
    assert alphabet == "Palu_996!?"
    assert target == "1145141919810"
    assert prefix == "palu{"
    assert suffix == "}"
    assert dialog_title == "flag"

    candidate_chars = []
    mapping = []
    for position, digit in enumerate(target):
        index = int(digit)
        if not 0 <= index < len(alphabet):
            raise ValueError(f"target digit {digit!r} outside alphabet at position {position}")
        char = alphabet[index]
        actual_index = alphabet.find(char)
        if actual_index != index:
            raise ValueError(
                f"index {index} is not reachable under first-match find(); "
                f"{char!r} first occurs at {actual_index}"
            )
        candidate_chars.append(char)
        mapping.append((position, digit, index, char, actual_index))

    candidate = "".join(candidate_chars)
    forward = "".join(str(alphabet.find(ch)) for ch in candidate)
    if forward != target:
        raise ValueError(f"forward transform mismatch: {forward!r} != {target!r}")
    candidate_bytes = candidate.encode("ascii", "strict")
    digest = hashlib.md5(candidate_bytes).hexdigest()
    flag = f"{prefix}{digest}{suffix}"

    print("mode=static-analysis-only; challenge EXE was not executed")
    print(f"archive_member={names[0]} size={len(archive_bytes)}")
    print(f"archive_extracted_bytes_match={archive_bytes == extracted_bytes}")
    print(f"original_sha256={sha256(packed_bytes)}")
    print(f"patched_sha256={sha256(patched_bytes)}")
    print(f"unpacked_reproduction_matches_saved={unpacked_bytes == known_unpacked_bytes}")
    print(f"unpacked_sha256={sha256(unpacked_bytes)} size={len(unpacked_bytes)}")
    print(f"pe_entry_rva={entry_rva:#x} image_base={image_base:#x}")
    print(f"sections={[(name, hex(rva), hex(raw_size), hex(raw_ptr)) for name, _, rva, raw_size, raw_ptr in sections]}")
    print(f"alphabet_rva={alphabet_rva:#x} alphabet={alphabet!r} length={len(alphabet)}")
    print(f"alphabet_positions={list(enumerate(alphabet))}")
    print(f"target_rva=0x5ea0 target={target!r} length={len(target)}")
    print(f"flag_prefix={prefix!r} flag_suffix={suffix!r} dialog_title={dialog_title!r}")
    print("mapping_position,target_digit,index,alphabet_char,first_find_index")
    for row in mapping:
        print(",".join((str(row[0]), row[1], str(row[2]), repr(row[3]), str(row[4]))))
    print(f"candidate_input={candidate!r}")
    print(f"candidate_input_ascii_hex={candidate_bytes.hex()}")
    print(f"forward_find_transform={forward}")
    print(f"forward_equals_target={forward == target}")
    print(f"md5_ascii_candidate={digest}")
    print(f"candidate_flag={flag}")


if __name__ == "__main__":
    main()

