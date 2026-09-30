"""Statically derived SM4 inverse for challenge #540; never executes the PE."""
from pathlib import Path

EXE = Path(__file__).with_name("unpacked") / "ezsignin.exe"
# The initializer's little-endian words are 0x04030201,
# 0x08070605, 0x12111009, 0x16151413.  Their in-memory bytes are
# 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 (hex).
KEY = bytes.fromhex("01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16")
TARGET = bytes.fromhex("1c84be5145ce1af31fa3f75e3a38d0be")
RDATA_FILE_OFFSET = 0x1800
RDATA_RVA = 0x3000
SBOX_RVA = 0x32A0


def rol32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def tau(x: int, sbox: bytes) -> int:
    return sum(sbox[(x >> shift) & 0xFF] << shift for shift in (24, 16, 8, 0))


def round_keys(key: bytes, sbox: bytes) -> list[int]:
    fk = (0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC)
    ck = [sum((((4 * i + j) * 7) & 0xFF) << (24 - 8 * j) for j in range(4)) for i in range(32)]
    mk = [int.from_bytes(key[i:i + 4], "big") for i in range(0, 16, 4)]
    k = [mk[i] ^ fk[i] for i in range(4)]
    rk = []
    for i in range(32):
        b = tau(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ ck[i], sbox)
        k.append((k[i] ^ b ^ rol32(b, 13) ^ rol32(b, 23)) & 0xFFFFFFFF)
        rk.append(k[-1])
    return rk


def crypt_block(block: bytes, rk: list[int], sbox: bytes) -> bytes:
    x = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 16, 4)]
    for i in range(32):
        b = tau(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i], sbox)
        x.append((x[i] ^ b ^ rol32(b, 2) ^ rol32(b, 10) ^ rol32(b, 18) ^ rol32(b, 24)) & 0xFFFFFFFF)
    return b"".join(v.to_bytes(4, "big") for v in reversed(x[-4:]))


def main() -> None:
    blob = EXE.read_bytes()
    sbox_off = RDATA_FILE_OFFSET + SBOX_RVA - RDATA_RVA
    sbox = blob[sbox_off:sbox_off + 256]
    assert len(sbox) == 256
    rk = round_keys(KEY, sbox)
    plaintext = crypt_block(TARGET, list(reversed(rk)), sbox)
    recovered = crypt_block(plaintext, rk, sbox)
    print(f"exe_sha256={__import__('hashlib').sha256(blob).hexdigest().upper()}")
    print(f"key_hex={KEY.hex().upper()}")
    print(f"sbox_first16={sbox[:16].hex().upper()}")
    print(f"sbox_last16={sbox[-16:].hex().upper()}")
    print(f"round_keys_first4={' '.join(f'{x:08X}' for x in rk[:4])}")
    print(f"round_keys_last4={' '.join(f'{x:08X}' for x in rk[-4:])}")
    print(f"target_hex={TARGET.hex().upper()}")
    print(f"candidate_hex={plaintext.hex().upper()}")
    print(f"candidate_repr={plaintext!r}")
    print(f"candidate_ascii={plaintext.decode('ascii', errors='backslashreplace')}")
    print(f"reencrypt_hex={recovered.hex().upper()}")
    print(f"reencrypt_matches_target={recovered == TARGET}")


if __name__ == "__main__":
    main()
