#!/usr/bin/env python3
"""Recover the 9-point pattern from OpenHarmony_secret's native verifier.

Evidence: libsecret.so::verifyPattern requires nine int32 values, copies the
hard-coded 9-word array, calls init_proc, and compares the transformed values
against that array. init_proc is the standard XXTEA encryption loop with
delta=0x9e3779b9 and rounds=6+52/n. The fixed key and target words are stored
in the ELF .data section as `what` and `is` respectively.
"""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

MASK = 0xFFFFFFFF
DELTA = 0x9E3779B9
DATA_FILE_OFFSET = 0xE720  # .data VMA 0x11720, file offset 0xE720
KEY_RELATIVE_OFFSET = 0x10  # `what` at VMA 0x11730
TARGET_RELATIVE_OFFSET = 0x20  # `is` at VMA 0x11740
WORDS = 9


def mx(z: int, y: int, total: int, key: tuple[int, ...], e: int, p: int) -> int:
    return (
        (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
        ^ ((total ^ y) + (key[(p & 3) ^ e] ^ z))
    ) & MASK


def encrypt(values: list[int], key: tuple[int, ...]) -> list[int]:
    v = [x & MASK for x in values]
    n = len(v)
    rounds = 6 + 52 // n
    total = 0
    z = v[-1]
    while rounds:
        total = (total + DELTA) & MASK
        e = (total >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            v[p] = (v[p] + mx(z, y, total, key, e, p)) & MASK
            z = v[p]
        y = v[0]
        v[-1] = (v[-1] + mx(z, y, total, key, e, n - 1)) & MASK
        z = v[-1]
        rounds -= 1
    return v


def decrypt(values: list[int], key: tuple[int, ...]) -> list[int]:
    v = [x & MASK for x in values]
    n = len(v)
    rounds = 6 + 52 // n
    total = (rounds * DELTA) & MASK
    y = v[0]
    while total:
        e = (total >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - mx(z, y, total, key, e, p)) & MASK
            y = v[p]
        z = v[-1]
        v[0] = (v[0] - mx(z, y, total, key, e, 0)) & MASK
        y = v[0]
        total = (total - DELTA) & MASK
    return v


def main() -> None:
    path = Path(sys.argv[1])
    blob = path.read_bytes()
    key = struct.unpack_from("<4I", blob, DATA_FILE_OFFSET + KEY_RELATIVE_OFFSET)
    target = list(
        struct.unpack_from("<9I", blob, DATA_FILE_OFFSET + TARGET_RELATIVE_OFFSET)
    )
    pattern = decrypt(target, key)
    check = encrypt(pattern, key)
    if check != target:
        raise SystemExit("round-trip check failed")

    # The ArkTS callback calls Array.toString(), which yields comma-separated
    # point indices. Keep the compact form only as an alternate because the
    # prose hint's example omits commas and its example digest is inconsistent.
    password_array_string = ",".join(str(value) for value in pattern)
    password_compact = "".join(str(value) for value in pattern)
    flag_digest_array = hashlib.md5(
        (password_array_string + "Harmony5337").encode("ascii")
    ).hexdigest()
    flag_digest_compact = hashlib.md5(
        (password_compact + "Harmony5337").encode("ascii")
    ).hexdigest()
    example_digest_computed = hashlib.md5(
        b"012345678Harmony5337"
    ).hexdigest()
    print(f"ELF attachment = {path}")
    print(f"key words       = {[hex(value) for value in key]}")
    print(f"target words    = {[hex(value) for value in target]}")
    print(f"decrypted words = {pattern}")
    print(f"re-encrypt      = {[hex(value) for value in check]}")
    print(f"round-trip      = {check == target}")
    print(f"PatternLock Array.toString() = {password_array_string}")
    print(f"compact candidate password  = {password_compact}")
    print(f"MD5(comma path+Harmony5337)  = {flag_digest_array}")
    print(f"MD5(compact+Harmony5337)     = {flag_digest_compact}")
    print(f"example digest in source     = 871f72716d85a6374f438ea70c2fd62c")
    print(f"example digest recomputed    = {example_digest_computed}")
    print(f"primary candidate flag      = flag{{{flag_digest_array}}}")
    print(f"alternate candidate flag    = flag{{{flag_digest_compact}}}")


if __name__ == "__main__":
    main()
