#!/usr/bin/env python3
"""Independently re-derive #561's native pattern without executing the HAP.

Only Python's standard library is used. The script reads ELF section metadata,
extracts the key and encrypted target from .data, decrypts with XXTEA, then
checks the answer by re-encrypting it. The final MD5 values are hypotheses from
the resource hint, not proof of a platform-accepted flag.
"""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ELF = ROOT / "附件" / "hap_contents" / "libs" / "x86_64" / "libsecret.so"
MASK = 0xFFFFFFFF
DELTA = 0x9E3779B9
KEY_REL = 0x10  # .data + 0x10: native object `what`, four uint32 words
TARGET_REL = 0x20  # .data + 0x20: native object `is`, nine uint32 words
SUFFIX = "Harmony5337"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")


def get_data_section(blob: bytes) -> tuple[int, int, int, int]:
    """Return ELF machine, .data file offset, size, and ELF class bits."""
    if blob[:4] != b"\x7fELF":
        raise ValueError("input is not an ELF file")
    elf_class, endian = blob[4], blob[5]
    if elf_class != 2 or endian != 1:
        raise ValueError("expected little-endian ELF64")
    fields = struct.unpack_from("<16sHHIQQQIHHHHHH", blob, 0)
    _ident, _etype, machine, _version, _entry, _phoff, shoff, _flags, _ehsize, _phentsize, _phnum, shentsize, shnum, shstrndx = fields
    if shentsize < 64 or shstrndx >= shnum:
        raise ValueError("invalid ELF section table")

    def section_header(index: int) -> tuple[int, ...]:
        off = shoff + index * shentsize
        if off + 64 > len(blob):
            raise ValueError("section header extends beyond file")
        return struct.unpack_from("<IIQQQQIIQQ", blob, off)

    strings_header = section_header(shstrndx)
    strings_off, strings_size = strings_header[4], strings_header[5]
    strings = blob[strings_off:strings_off + strings_size]
    for index in range(shnum):
        header = section_header(index)
        name_off = header[0]
        if name_off >= len(strings):
            continue
        end = strings.find(b"\0", name_off)
        name = strings[name_off:end if end >= 0 else len(strings)].decode("ascii", "replace")
        if name == ".data":
            return machine, header[4], header[5], elf_class * 32
    raise ValueError("ELF has no .data section")


def mx(z: int, y: int, total: int, key: tuple[int, ...], e: int, p: int) -> int:
    a = ((z >> 5) ^ ((y << 2) & MASK))
    b = ((y >> 3) ^ ((z << 4) & MASK))
    c = ((total ^ y) + (key[(p & 3) ^ e] ^ z)) & MASK
    return ((a + b) ^ c) & MASK


def xxtea_encrypt(words: list[int], key: tuple[int, ...]) -> list[int]:
    values = [value & MASK for value in words]
    n = len(values)
    rounds = 6 + 52 // n
    total = 0
    z = values[-1]
    while rounds:
        total = (total + DELTA) & MASK
        e = (total >> 2) & 3
        for p in range(n - 1):
            y = values[p + 1]
            values[p] = (values[p] + mx(z, y, total, key, e, p)) & MASK
            z = values[p]
        y = values[0]
        values[-1] = (values[-1] + mx(z, y, total, key, e, n - 1)) & MASK
        z = values[-1]
        rounds -= 1
    return values


def xxtea_decrypt(words: list[int], key: tuple[int, ...]) -> list[int]:
    values = [value & MASK for value in words]
    n = len(values)
    rounds = 6 + 52 // n
    total = (rounds * DELTA) & MASK
    y = values[0]
    while total:
        e = (total >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = values[p - 1]
            values[p] = (values[p] - mx(z, y, total, key, e, p)) & MASK
            y = values[p]
        z = values[-1]
        values[0] = (values[0] - mx(z, y, total, key, e, 0)) & MASK
        y = values[0]
        total = (total - DELTA) & MASK
    return values


def md5(text: str) -> str:
    return hashlib.md5(text.encode("ascii")).hexdigest()


def words_hex(values: list[int] | tuple[int, ...]) -> list[str]:
    return [f"0x{value:08x}" for value in values]


def main() -> None:
    blob = ELF.read_bytes()
    machine, data_off, data_size, bits = get_data_section(blob)
    if machine != 62:
        raise ValueError(f"expected x86_64 ELF machine 62, found {machine}")
    if data_size < TARGET_REL + 9 * 4:
        raise ValueError(".data section is too short for expected native constants")
    key = struct.unpack_from("<4I", blob, data_off + KEY_REL)
    target = list(struct.unpack_from("<9I", blob, data_off + TARGET_REL))
    pattern = xxtea_decrypt(target, key)
    rebuilt = xxtea_encrypt(pattern, key)
    compact = "".join(str(point) for point in pattern)
    comma = ",".join(str(point) for point in pattern)
    one_based = "".join(str(point + 1) for point in pattern)

    print(f"ELF_PATH_REL={ELF.relative_to(ROOT).as_posix()}")
    print(f"ELF_BITS={bits} MACHINE={machine} SIZE={len(blob)}")
    print(f"ELF_SHA256={hashlib.sha256(blob).hexdigest().upper()}")
    print(f"DATA_FILE_OFFSET=0x{data_off:x} DATA_SIZE=0x{data_size:x}")
    print(f"KEY_OFFSET=0x{data_off + KEY_REL:x} KEY_WORDS={words_hex(key)}")
    print(f"TARGET_OFFSET=0x{data_off + TARGET_REL:x} TARGET_WORDS={words_hex(target)}")
    print(f"DECRYPTED_PATTERN={pattern}")
    print(f"REENCRYPTED_WORDS={words_hex(rebuilt)}")
    print(f"XXTEA_ROUNDTRIP={rebuilt == target}")
    print(f"COMPACT_ZERO_BASED={compact!r}")
    print(f"ARRAY_TOSTRING={comma!r}")
    print(f"SHIFTED_ONE_BASED={one_based!r}")
    for name, password in (
        ("compact zero-based; hint says no comma", compact),
        ("JavaScript array text; comma-separated", comma),
        ("shifted one-based labels", one_based),
        ("hint example input", "012345678"),
    ):
        full_input = password + SUFFIX
        print(f"MD5_VARIANT={name!r} INPUT={full_input!r} DIGEST={md5(full_input)}")
    stated_example = "871f72716d85a6374f438ea70c2fd62c"
    computed_example = md5("012345678" + SUFFIX)
    print(f"PROMPT_STATED_EXAMPLE={stated_example}")
    print(f"PROMPT_EXAMPLE_RECOMPUTED={computed_example}")
    print("FLAG_STATUS=locally_derived_candidates_only; platform acceptance is not established here")
    assert rebuilt == target, "XXTEA encryption/decryption round-trip failed"
    assert pattern == [1, 3, 7, 5, 2, 4, 8, 6, 0], "unexpected pattern; inspect disassembly and offsets"


if __name__ == "__main__":
    main()

