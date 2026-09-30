from pathlib import Path
import hashlib
import struct

ROOT = Path(__file__).resolve().parents[1]
EXTRACTED = ROOT / "extracted"
ANALYSIS = ROOT / "analysis"

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def rol32(x: int, n: int) -> int:
    x &= 0xffffffff
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xffffffff
    s[d] = rol32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff
    s[b] = rol32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xffffffff
    s[d] = rol32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff
    s[b] = rol32(s[b] ^ s[c], 7)

def chacha20_block(initial: bytes) -> bytes:
    assert len(initial) == 64
    words = list(struct.unpack("<16I", initial))
    s = words.copy()
    for _ in range(10):
        qr(s, 0, 4, 8, 12)
        qr(s, 1, 5, 9, 13)
        qr(s, 2, 6, 10, 14)
        qr(s, 3, 7, 11, 15)
        qr(s, 0, 5, 10, 15)
        qr(s, 1, 6, 11, 12)
        qr(s, 2, 7, 8, 13)
        qr(s, 3, 4, 9, 14)
    return struct.pack("<16I", *(((x + y) & 0xffffffff) for x, y in zip(s, words)))

enc1 = (EXTRACTED / "1.enc").read_bytes()
enc2 = (EXTRACTED / "2.enc").read_bytes()
exe = (EXTRACTED / "人生自古谁无死.exe").read_bytes()
# .rdata @ VA 0x405050, exactly 30 bytes copied by handle_strings.
decoy = bytes.fromhex("28 21 3c 38 37 20 26 0a 21 3a 3b 0a 3a 31 0a 32 34 39 33 0a 30 3e 34 33 2e 13 01 16 04 06")
decoy_transformed = bytearray(decoy)
for i in range(29):
    decoy_transformed[i] ^= 0x55
# flip_bytes(decoy, 29), with floor(29/2)=14 swaps.
for i in range(29 // 2):
    j = 29 - i - 1
    decoy_transformed[i], decoy_transformed[j] = decoy_transformed[j], decoy_transformed[i]

# .data @ VA 0x404020 ("expand 32-byte k") and 0x404040 (DWORD 0xDEADBEEF).
constant = b"expand 32-byte k"
g_obf2 = bytes.fromhex("de ad be ef")
obfuscated_material = bytes(((i + 0x11) ^ g_obf2[i % 4]) & 0xff for i in range(32))
# handle_strings explicitly zeroes state[48:52], then writes i*17 to state[52:64].
initial_state = constant + obfuscated_material + bytes(4) + bytes((i * 17) & 0xff for i in range(12))
assert len(initial_state) == 64
keystream = chacha20_block(initial_state)
plain2 = xor(enc2, keystream)
plain1_with_stream = xor(enc1, keystream[:len(enc1)])
# Independently apply the binary-revealed byte transforms directly to the attached 1.enc.
plain1_transform = xor(enc1[::-1], bytes([0x55]) * len(enc1))
embedded_target = bytes.fromhex("d0 a1 14 b7 58 fa 85 91 41 53 1b 60 38 ab a5 02 29 cb dd 28 4e 67 e6 32 d9")
transformed_target = xor(embedded_target, keystream[:len(embedded_target)])

print("EXE sha256:", hashlib.sha256(exe).hexdigest().upper())
print("1.enc sha256:", hashlib.sha256(enc1).hexdigest().upper(), "length", len(enc1))
print("2.enc sha256:", hashlib.sha256(enc2).hexdigest().upper(), "length", len(enc2))
print("decoy source bytes (30):", decoy.hex(" "))
print("decoy transform first 29 XOR 0x55 then reverse first 29:", decoy_transformed.hex(" "))
print("decoy transformed repr:", repr(bytes(decoy_transformed)))
print("state[0:16] ascii:", constant)
print("g_obf2 bytes:", g_obf2.hex(" "))
print("state[16:48] decoded bytes:", obfuscated_material.hex(" "))
print("state[52:64]:", initial_state[52:].hex(" "))
print("state words:", " ".join(f"{w:08x}" for w in struct.unpack("<16I", initial_state)))
print("ChaCha20-style block output:", keystream.hex(" "))
print("2.enc XOR block -> candidate:", plain2)
print("2.enc XOR block -> hex:", plain2.hex(" "))
print("1.enc reverse + XOR 0x55 -> candidate:", repr(plain1_transform))
print("1.enc transform hex:", plain1_transform.hex(" "))
print("1.enc XOR block (alternate only):", repr(plain1_with_stream))
print("embedded target XOR block ->:", repr(transformed_target))
print("embedded target transformed hex:", transformed_target.hex(" "))



