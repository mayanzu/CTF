#!/usr/bin/env python3
"""Independent Python reference for ParlooChecker's statically recovered cipher."""
from pathlib import Path
import hashlib
import struct

BASE = Path(__file__).parent
LIBDIR = BASE / "code" / "lib"
MASK = 0xFFFFFFFF
D = 0x9E3779B9
FLAG_CIPHERTEXT = bytes.fromhex(
    "af9008e79057a3edb1052dba56c04fd3"
    "fcaab795eee49f1ae92c21fc292ece52"
    "c48cf041e9890d79"
)
RC4_PASSWORD = b"DoNotHackMe"
KEY_CIPHERTEXT = bytes.fromhex("99dd56ff6dd95554424d791a34b7812f")
IV_CIPHERTEXT = bytes.fromhex("87c156c04cf4634f")

def rc4_reference(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for n in range(256):
        j = (j + s[n] + key[n % len(key)]) & 255
        s[n], s[j] = s[j], s[n]
    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) & 255
        j = (j + s[i]) & 255
        s[i], s[j] = s[j], s[i]
        result.append(byte ^ s[(s[i] + s[j]) & 255])
    return bytes(result)

def mix_reference(word: int) -> int:
    # Direct transcription of (v << 4 XOR v >> 5) + v from 0x28b20.
    return ((((word << 4) & MASK) ^ (word >> 5)) + word) & MASK

def xtea_variant_encrypt(block: bytes, key: tuple[int, ...]) -> bytes:
    left, right = struct.unpack("<II", block)
    total = 0
    for round_no in range(32):
        left = (left + (mix_reference(right) ^ ((total + key[total & 3]) & MASK))) & MASK
        increment = (D + (key[round_no & 3] ^ round_no)) & MASK
        total = (total + increment) & MASK
        right = (right + (mix_reference(left) ^ ((total + key[(total >> 11) & 3]) & MASK))) & MASK
    return struct.pack("<II", left, right)

def xtea_variant_decrypt(block: bytes, key: tuple[int, ...]) -> bytes:
    left, right = struct.unpack("<II", block)
    totals = [0]
    for round_no in range(32):
        totals.append((totals[-1] + D + (key[round_no & 3] ^ round_no)) & MASK)
    for round_no in range(31, -1, -1):
        total_after = totals[round_no + 1]
        right = (right - (mix_reference(left) ^ ((total_after + key[(total_after >> 11) & 3]) & MASK))) & MASK
        total_before = totals[round_no]
        left = (left - (mix_reference(right) ^ ((total_before + key[total_before & 3]) & MASK))) & MASK
    return struct.pack("<II", left, right)

def cbc_reference(ciphertext: bytes, key: tuple[int, ...], iv: bytes) -> bytes:
    previous = iv
    plain = bytearray()
    for offset in range(0, len(ciphertext), 8):
        current = ciphertext[offset:offset + 8]
        block = xtea_variant_decrypt(current, key)
        plain.extend(x ^ y for x, y in zip(block, previous))
        previous = current
    return bytes(plain)

def cbc_encrypt_reference(plaintext: bytes, key: tuple[int, ...], iv: bytes) -> bytes:
    previous = iv
    output = bytearray()
    for offset in range(0, len(plaintext), 8):
        block = bytes(x ^ y for x, y in zip(plaintext[offset:offset + 8], previous))
        current = xtea_variant_encrypt(block, key)
        output.extend(current)
        previous = current
    return bytes(output)

def main() -> None:
    key_material = rc4_reference(RC4_PASSWORD, KEY_CIPHERTEXT)
    iv = rc4_reference(RC4_PASSWORD, IV_CIPHERTEXT)
    key = struct.unpack("<4I", key_material)
    print(f"REF_RC4_KEY={key_material.hex()!r}")
    print(f"REF_RC4_IV={iv.hex()!r}")
    padded = cbc_reference(FLAG_CIPHERTEXT, key, iv)
    pad = padded[-1]
    if not 1 <= pad <= 8 or padded[-pad:] != bytes([pad]) * pad:
        raise ValueError(f"reference PKCS7 validation failed: {padded[-8:].hex()}")
    candidate = padded[:-pad]
    print(f"REF_DECRYPTED_PADDED={padded.hex()}")
    print(f"REF_PAD_BYTE={pad:02x}; REF_PAD_VALID=True")
    print(f"REF_CANDIDATE={candidate.decode('ascii')}")
    print(f"REF_CBC_REENCRYPT_MATCH={cbc_encrypt_reference(padded, key, iv) == FLAG_CIPHERTEXT}")
    sample = bytes.fromhex("0001020304050607")
    print(f"REF_BLOCK_SELFTEST={xtea_variant_decrypt(xtea_variant_encrypt(sample, key), key) == sample}")
    for abi in ("x86_64", "x86", "arm64-v8a", "armeabi-v7a"):
        path = LIBDIR / abi / "libparloo.so"
        data = path.read_bytes()
        matches = {
            "target": data.find(FLAG_CIPHERTEXT),
            "rc4_key": data.find(RC4_PASSWORD),
            "enc_key": data.find(KEY_CIPHERTEXT),
            "enc_iv": data.find(IV_CIPHERTEXT),
        }
        print(f"ABI={abi} SHA256={hashlib.sha256(data).hexdigest().upper()} OFFSETS={matches} ALL_CONSTANTS_PRESENT={all(x >= 0 for x in matches.values())}")

if __name__ == "__main__":
    main()
