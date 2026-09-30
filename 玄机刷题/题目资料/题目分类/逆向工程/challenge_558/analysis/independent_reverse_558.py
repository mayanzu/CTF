from pathlib import Path

# Static-only reproduction of the transform recovered from R.exe.
key_literal = b"lntfvpus"
key = bytes(value ^ index for index, value in enumerate(key_literal))
target = bytes.fromhex("18 59 07 28 f4 ad c8 c3 b6 3f 2d 39 ca 34 d1 8e f5 03 b0")
assert len(target) == 19 and len(key) == 8

# KSA: j = (j + S[i] + (key[i % 8] ^ 0x66)) mod 256; swap S[i], S[j].
S = list(range(256))
j = 0
for i in range(256):
    j = (j + S[i] + (key[i % len(key)] ^ 0x66)) & 0xff
    S[i], S[j] = S[j], S[i]

# Invert output = ((plain ^ (nibble_swap(K) + 1)) + 1) mod 256.
# PRGA K = S[(S[i] + S[j]) mod 256] after swapping.
i = j = 0
plain = bytearray()
keystream = bytearray()
for c in target:
    i = (i + 1) & 0xff
    j = (j + S[i]) & 0xff
    S[i], S[j] = S[j], S[i]
    k = S[(S[i] + S[j]) & 0xff]
    mask = (((k << 4) | (k >> 4)) & 0xff) + 1
    mask &= 0xff
    keystream.append(mask)
    # Inverse: plain = ((cipher - 1) mod 256) XOR mask.
    plain.append(((c - 1) & 0xff) ^ mask)

# Independent forward calculation against the hard-coded byte target.
S2 = list(range(256))
j = 0
for i in range(256):
    j = (j + S2[i] + (key[i % len(key)] ^ 0x66)) & 0xff
    S2[i], S2[j] = S2[j], S2[i]
i = j = 0
forward = bytearray()
for p in plain:
    i = (i + 1) & 0xff
    j = (j + S2[i]) & 0xff
    S2[i], S2[j] = S2[j], S2[i]
    k = S2[(S2[i] + S2[j]) & 0xff]
    mask = ((((k << 4) | (k >> 4)) & 0xff) + 1) & 0xff
    forward.append((((p ^ mask) + 1) & 0xff))

print("key literal ASCII:", key_literal.decode("ascii"))
print("key after byte[i] ^= i:", key.decode("ascii"))
print("KSA byte formula: key[i % 8] ^ 0x66")
print("target length:", len(target))
print("candidate hex:", plain.hex())
print("candidate repr:", repr(bytes(plain)))
print("candidate ASCII:", bytes(plain).decode("ascii", errors="backslashreplace"))
print("starts flag{:", bytes(plain).startswith(b"flag{"))
print("forward hex:", forward.hex())
print("full target match:", bytes(forward) == target)
