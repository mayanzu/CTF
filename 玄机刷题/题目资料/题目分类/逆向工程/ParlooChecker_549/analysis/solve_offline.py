#!/usr/bin/env python3
"""Recover ParlooChecker's expected input from static ELF constants only.

No APK or shared library code is loaded or executed by this script.
"""
from pathlib import Path
import hashlib
import struct
import sys

LIB = Path(__file__).parent / "code" / "lib" / "x86_64" / "libparloo.so"
MASK = 0xFFFFFFFF
DELTA = 0x9E3779B9
RODATA_OFFSETS_EQUAL_VADDRS = True  # readelf -S: .rodata sh_addr == sh_offset == 0xea00.

def static_bytes(address: int, length: int) -> bytes:
    if not RODATA_OFFSETS_EQUAL_VADDRS:
        raise RuntimeError("ELF VMA-to-file-offset mapping must be verified first")
    data = LIB.read_bytes()
    if address < 0 or address + length > len(data):
        raise ValueError("requested data is outside the ELF file")
    return data[address:address+length]

def rc4_xor(key: bytes, data: bytes) -> bytes:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        stream = state[(state[i] + state[j]) & 0xFF]
        out.append(byte ^ stream)
    return bytes(out)

def u32le(data: bytes) -> int:
    return struct.unpack('<I', data)[0]

def tea_mix(v: int) -> int:
    return ((((v << 4) & MASK) ^ (v >> 5)) + v) & MASK

def round_increment(key: tuple[int, int, int, int], round_index: int) -> int:
    """Native code adds DELTA + (key[round_index & 3] XOR round_index)."""
    return (DELTA + (key[round_index & 3] ^ round_index)) & MASK

def tea_encrypt(block: bytes, key: tuple[int, int, int, int]) -> bytes:
    v0, v1 = struct.unpack('<2I', block)
    total = 0
    for round_index in range(32):
        v0 = (v0 + (tea_mix(v1) ^ ((total + key[total & 3]) & MASK))) & MASK
        total = (total + round_increment(key, round_index)) & MASK
        v1 = (v1 + (tea_mix(v0) ^ ((total + key[(total >> 11) & 3]) & MASK))) & MASK
    return struct.pack('<2I', v0, v1)

def tea_decrypt(block: bytes, key: tuple[int, int, int, int]) -> bytes:
    v0, v1 = struct.unpack('<2I', block)
    total = 0
    for round_index in range(32):
        total = (total + round_increment(key, round_index)) & MASK
    for round_index in reversed(range(32)):
        v1 = (v1 - (tea_mix(v0) ^ ((total + key[(total >> 11) & 3]) & MASK))) & MASK
        total = (total - round_increment(key, round_index)) & MASK
        v0 = (v0 - (tea_mix(v1) ^ ((total + key[total & 3]) & MASK))) & MASK
    return struct.pack('<2I', v0, v1)

def cbc_encrypt(data: bytes, key: tuple[int, int, int, int], iv: bytes) -> bytes:
    if len(data) % 8:
        raise ValueError("TEA-CBC plaintext must be block aligned")
    out = bytearray()
    prev = iv
    for off in range(0, len(data), 8):
        mixed = bytes(a ^ b for a, b in zip(data[off:off+8], prev))
        block = tea_encrypt(mixed, key)
        out.extend(block)
        prev = block
    return bytes(out)

def cbc_decrypt(data: bytes, key: tuple[int, int, int, int], iv: bytes) -> bytes:
    if len(data) % 8:
        raise ValueError("TEA-CBC ciphertext must be block aligned")
    out = bytearray()
    prev = iv
    for off in range(0, len(data), 8):
        block = data[off:off+8]
        plain = tea_decrypt(block, key)
        out.extend(a ^ b for a, b in zip(plain, prev))
        prev = block
    return bytes(out)

def pkcs7_unpad(data: bytes, block_size: int = 8) -> bytes:
    if not data or len(data) % block_size:
        raise ValueError("invalid padded plaintext length")
    pad = data[-1]
    if not (1 <= pad <= block_size) or data[-pad:] != bytes([pad]) * pad:
        raise ValueError(f"invalid PKCS#7 bytes: {data[-8:].hex()}")
    return data[:-pad]

def main() -> None:
    raw = LIB.read_bytes()
    print(f"LIB={LIB}")
    print(f"LIB_SIZE={len(raw)} SHA256={hashlib.sha256(raw).hexdigest().upper()}")
    target = static_bytes(0x10130, 0x28)
    rc4_key = static_bytes(0x10158, 0x0B)
    enc_tea_key = static_bytes(0x10170, 0x10)
    enc_iv = static_bytes(0x10180, 0x08)
    tea_key_raw = rc4_xor(rc4_key, enc_tea_key)
    iv = rc4_xor(rc4_key, enc_iv)
    key = struct.unpack('<4I', tea_key_raw)
    print(f"RC4_KEY_ASCII={rc4_key!r}")
    print(f"TARGET_CIPHERTEXT_LEN={len(target)} HEX={target.hex()}")
    print(f"ENCRYPTED_TEA_KEY={enc_tea_key.hex()}")
    print(f"TEA_KEY_RAW={tea_key_raw.hex()}")
    print("TEA_KEY_U32LE=" + ",".join(f"0x{x:08x}" for x in key))
    print(f"ENCRYPTED_IV={enc_iv.hex()}")
    print(f"IV={iv.hex()}")
    sample_block = bytes(range(8))
    sample_encrypted = tea_encrypt(sample_block, key)
    sample_decrypted = tea_decrypt(sample_encrypted, key)
    print(f"BLOCK_CIPHER_SELFTEST_INPUT={sample_block.hex()}")
    print(f"BLOCK_CIPHER_SELFTEST_ENCRYPTED={sample_encrypted.hex()}")
    print(f"BLOCK_CIPHER_SELFTEST_DECRYPTED={sample_decrypted.hex()}")
    print(f"BLOCK_CIPHER_SELFTEST_MATCH={sample_decrypted == sample_block}")
    padded = cbc_decrypt(target, key, iv)
    candidate = pkcs7_unpad(padded)
    print(f"DECRYPTED_PADDED_HEX={padded.hex()}")
    print(f"PKCS7_PADDING_LEN={padded[-1]}")
    print(f"CANDIDATE_LEN={len(candidate)}")
    print(f"CANDIDATE_BYTES={candidate!r}")
    try:
        print(f"CANDIDATE_UTF8={candidate.decode('utf-8')}")
    except UnicodeDecodeError as exc:
        print(f"CANDIDATE_UTF8_ERROR={exc}")
    re_padded = candidate + bytes([len(padded)-len(candidate)]) * (len(padded)-len(candidate))
    recreated = cbc_encrypt(re_padded, key, iv)
    print(f"ROUNDTRIP_TARGET_MATCH={recreated == target}")
    print(f"ROUNDTRIP_CIPHERTEXT={recreated.hex()}")
    print(f"FLAG_WRAPPER_CHECK={candidate.startswith(b'flag{') and candidate.endswith(b'}')}")
    if len(sys.argv) > 1:
        supplied = sys.argv[1].encode('utf-8')
        test_padded = supplied + bytes([8 - (len(supplied) % 8)]) * (8 - (len(supplied) % 8))
        print(f"SUPPLIED_INPUT={supplied!r}")
        print(f"SUPPLIED_CIPHERTEXT_MATCH={cbc_encrypt(test_padded,key,iv)==target}")

if __name__ == "__main__":
    main()
