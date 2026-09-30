"""Independently rederive the native pattern and hash-string variants from ELF data."""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ELF = ROOT / "hap_contents" / "libs" / "x86_64" / "libsecret.so"
MASK = 0xFFFFFFFF
DELTA = 0x9E3779B9
DATA_OFF = 0xE720


def mix(z: int, y: int, total: int, key: tuple[int, ...], e: int, p: int) -> int:
    a = ((z >> 5) ^ ((y << 2) & MASK))
    b = ((y >> 3) ^ ((z << 4) & MASK))
    c = ((total ^ y) + (key[(p & 3) ^ e] ^ z)) & MASK
    return ((a + b) ^ c) & MASK


def xxtea_encrypt(words: list[int], key: tuple[int, ...]) -> list[int]:
    values = [w & MASK for w in words]
    count = len(values)
    rounds = 6 + 52 // count
    total = 0
    z = values[-1]
    while rounds:
        total = (total + DELTA) & MASK
        e = (total >> 2) & 3
        for p in range(count - 1):
            y = values[p + 1]
            values[p] = (values[p] + mix(z, y, total, key, e, p)) & MASK
            z = values[p]
        y = values[0]
        values[-1] = (values[-1] + mix(z, y, total, key, e, count - 1)) & MASK
        z = values[-1]
        rounds -= 1
    return values


def xxtea_decrypt(words: list[int], key: tuple[int, ...]) -> list[int]:
    values = [w & MASK for w in words]
    count = len(values)
    rounds = 6 + 52 // count
    total = (rounds * DELTA) & MASK
    y = values[0]
    while total:
        e = (total >> 2) & 3
        for p in range(count - 1, 0, -1):
            z = values[p - 1]
            values[p] = (values[p] - mix(z, y, total, key, e, p)) & MASK
            y = values[p]
        z = values[-1]
        values[0] = (values[0] - mix(z, y, total, key, e, 0)) & MASK
        y = values[0]
        total = (total - DELTA) & MASK
    return values


def digest(text: str) -> str:
    return hashlib.md5(text.encode("ascii")).hexdigest()


def main() -> None:
    blob = ELF.read_bytes()
    key = struct.unpack_from("<4I", blob, DATA_OFF + 0x10)
    target = list(struct.unpack_from("<9I", blob, DATA_OFF + 0x20))
    path = xxtea_decrypt(target, key)
    roundtrip = xxtea_encrypt(path, key)
    compact = "".join(str(value) for value in path)
    comma = ",".join(str(value) for value in path)
    print(f"ELF={ELF}")
    print(f"ELF_SIZE={len(blob)} SHA256={hashlib.sha256(blob).hexdigest().upper()}")
    print(f"DATA_FILE_OFFSET=0x{DATA_OFF:x} KEY_OFFSET=0x{DATA_OFF+0x10:x} TARGET_OFFSET=0x{DATA_OFF+0x20:x}")
    print(f"KEY_WORDS={[hex(value) for value in key]}")
    print(f"TARGET_WORDS={[hex(value) for value in target]}")
    print(f"DECRYPTED_PATTERN={path}")
    print(f"REENCRYPTED_WORDS={[hex(value) for value in roundtrip]}")
    print(f"XXTEA_ROUNDTRIP={roundtrip == target}")
    print(f"ZERO_BASED_COMPACT={compact!r}")
    print(f"ARRAY_TOSTRING={comma!r}")
    print(f"ONE_BASED_COMPACT={''.join(str(value+1) for value in path)!r}")
    suffix = "Harmony5337"
    for label, password in (
        ("actual path compact (hint says no comma)", compact),
        ("actual path JS Array.toString", comma),
        ("actual path shifted to 1-based labels", "".join(str(value + 1) for value in path)),
        ("sample path from prompt", "012345678"),
        ("1-based natural-order sample", "123456789"),
    ):
        print(f"MD5_VARIANT {label}: input={password + suffix!r} digest={digest(password + suffix)}")
    print(f"PROMPT_SAMPLE_DIGEST=871f72716d85a6374f438ea70c2fd62c")
    print(f"PROMPT_SAMPLE_RECOMPUTED={digest('012345678' + suffix)}")
    assert roundtrip == target


if __name__ == "__main__":
    main()
