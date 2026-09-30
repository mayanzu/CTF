#!/usr/bin/env python3
"""Recover the 16-byte plaintext checked by ezsignin.exe using SM4 decryption."""

from __future__ import annotations

MASK = 0xFFFFFFFF
SBOX = bytes.fromhex(
    "d690e9fecce13db716b614c228fb2c05"
    "2b679a762abe04c3aa44132649860699"
    "9c4250f491ef987a33540b43edcfac62"
    "e4b31ca9c908e89580df94fa758f3fa6"
    "4707a7fcf37317ba83593c19e6854fa8"
    "686b81b27164da8bf8eb0f4b70569d35"
    "1e240e5e6358d1a225227c3b01217887"
    "d40046579fd327524c3602e7a0c4c89e"
    "eabf8ad240c738b5a3f7f2cef96115a1"
    "e0ae5da49b341a55ad933230f58cb1e3"
    "1df6e22e8266ca60c02923ab0d534e6f"
    "d5db3745defd8e2f03ff6a726d6c5b51"
    "8d1baf92bbddbc7f11d95c411f105ad8"
    "0ac13188a5cd7bbd2d74d012b8e5b4b0"
    "8969974a0c96777e65b9f109c56ec684"
    "18f07dec3adc4d2079ee5f3ed7cb3948"
)
FK = (0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC)
CK = tuple(
    int.from_bytes(bytes((i * 4 * 7 & 0xFF, (i * 4 + 1) * 7 & 0xFF,
                          (i * 4 + 2) * 7 & 0xFF, (i * 4 + 3) * 7 & 0xFF)), "big")
    for i in range(32)
)


def rol32(value: int, count: int) -> int:
    value &= MASK
    return ((value << count) | (value >> (32 - count))) & MASK


def tau(value: int) -> int:
    return sum(SBOX[(value >> (24 - 8 * i)) & 0xFF] << (24 - 8 * i)
               for i in range(4))


def t_encrypt(value: int) -> int:
    b = tau(value)
    return b ^ rol32(b, 2) ^ rol32(b, 10) ^ rol32(b, 18) ^ rol32(b, 24)


def t_key(value: int) -> int:
    b = tau(value)
    return b ^ rol32(b, 13) ^ rol32(b, 23)


def round_keys(key: bytes) -> list[int]:
    if len(key) != 16:
        raise ValueError("SM4 key must be 16 bytes")
    k = [int.from_bytes(key[i:i + 4], "big") ^ FK[i // 4]
         for i in range(0, 16, 4)]
    result = []
    for i in range(32):
        nxt = k[i] ^ t_key(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i])
        k.append(nxt & MASK)
        result.append(nxt & MASK)
    return result


def crypt_block(block: bytes, key: bytes, decrypt: bool = False) -> bytes:
    if len(block) != 16:
        raise ValueError("SM4 operates on 16-byte blocks")
    rks = round_keys(key)
    if decrypt:
        rks.reverse()
    x = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 16, 4)]
    for i in range(32):
        x.append((x[i] ^ t_encrypt(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rks[i])) & MASK)
    return b"".join(v.to_bytes(4, "big") for v in reversed(x[32:36]))


def main() -> None:
    # Main's four little-endian dword immediates construct bytes
    # 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 (hex) in memory.
    key = bytes.fromhex("01020304050607080910111213141516")
    # Four dword immediates at 0x1400015b4..0x1400015c6, in memory order.
    target = bytes.fromhex("1c84be5145ce1af31fa3f75e3a38d0be")
    known_key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    known_cipher = bytes.fromhex("681edf34d206965e86b3e94f536e4246")
    assert crypt_block(known_key, known_key) == known_cipher
    plaintext = crypt_block(target, key, decrypt=True)
    assert crypt_block(plaintext, key) == target
    print(f"key bytes (from main local buffer) = {key.hex()}")
    print(f"target bytes (first 16 compared)  = {target.hex()}")
    print(f"SM4 known vector                  = OK")
    print(f"decrypted plaintext hex           = {plaintext.hex()}")
    print(f"decrypted plaintext repr          = {plaintext!r}")
    print(f"SM4 re-encrypt                    = {crypt_block(plaintext, key).hex()}")
    print(f"round-trip                        = True")


if __name__ == "__main__":
    main()
