#!/usr/bin/env python3
"""Recover the checker challenge flag directly from the PE attachment.

Only Python's standard library is used. The XOR key 0x23 is taken from the
immediate constant assigned in _encrypt_flag (checker_disassembly.txt).
"""

from __future__ import annotations

import hashlib
import re
import struct
import sys
from pathlib import Path


DEFAULT_EXE = Path(__file__).resolve().parents[1] / "附件_20260929" / "checker.exe"
TARGET_VA = 0x404020
XOR_KEY = 0x23


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def parse_pe_sections(data: bytes):
    if data[:2] != b"MZ":
        raise ValueError("missing DOS MZ signature")
    pe_off = u32(data, 0x3C)
    if data[pe_off : pe_off + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    coff = pe_off + 4
    machine = u16(data, coff)
    section_count = u16(data, coff + 2)
    optional_size = u16(data, coff + 16)
    optional = coff + 20
    magic = u16(data, optional)
    if magic != 0x10B:
        raise ValueError(f"expected PE32 optional header, got 0x{magic:04x}")
    image_base = u32(data, optional + 28)
    section_table = optional + optional_size
    sections = []
    for index in range(section_count):
        off = section_table + index * 40
        name = data[off : off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from(
            "<IIII", data, off + 8
        )
        sections.append(
            (name, virtual_size, virtual_address, raw_size, raw_ptr)
        )
    return machine, image_base, sections


def va_to_file_offset(va: int, image_base: int, sections) -> tuple[int, str]:
    rva = va - image_base
    for name, virtual_size, virtual_address, raw_size, raw_ptr in sections:
        span = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + span:
            delta = rva - virtual_address
            if delta >= raw_size:
                raise ValueError(f"VA 0x{va:x} has no raw file byte in {name}")
            return raw_ptr + delta, name
    raise ValueError(f"VA 0x{va:x} is not mapped by a PE section")


def main() -> int:
    exe = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_EXE
    data = exe.read_bytes()
    digest = hashlib.sha256(data).hexdigest().upper()
    machine, image_base, sections = parse_pe_sections(data)
    file_off, section_name = va_to_file_offset(TARGET_VA, image_base, sections)
    end = data.find(b"\0", file_off)
    if end < 0:
        raise ValueError("encrypted target has no terminating NUL")
    cipher = data[file_off:end]
    plain = bytes(value ^ XOR_KEY for value in cipher)
    round_trip = bytes(value ^ XOR_KEY for value in plain)

    print(f"input file: {exe}")
    print(f"file size: {len(data)} bytes")
    print(f"SHA-256: {digest}")
    print(f"PE machine: 0x{machine:04x} (i386 expected 0x014c)")
    print(f"image base: 0x{image_base:08x}")
    print(f"target VA: 0x{TARGET_VA:08x}")
    print(f"mapped section: {section_name}")
    print(f"target file offset: 0x{file_off:x}")
    print(f"cipher length: {len(cipher)} bytes")
    print(f"cipher hex: {cipher.hex(' ').upper()}")
    print(f"XOR key: 0x{XOR_KEY:02x}")
    print(f"plaintext hex: {plain.hex(' ').upper()}")
    print(f"plaintext ASCII: {plain.decode('ascii')}")
    print(f"re-XOR matches embedded bytes: {round_trip == cipher}")
    print(f"flag format valid: {bool(re.fullmatch(rb'flag\{[A-Za-z0-9_]+\}', plain))}")
    print(f"candidate length: {len(plain)} characters")

    if machine != 0x014C:
        raise ValueError("attachment is not PE i386")
    if not re.fullmatch(rb"flag\{[A-Za-z0-9_]+\}", plain):
        raise ValueError("decoded bytes do not match the observed flag format")
    if round_trip != cipher:
        raise ValueError("XOR round-trip did not reproduce target bytes")
    print(f"candidate flag: {plain.decode('ascii')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
