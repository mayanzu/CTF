MASK = 0xffffffff
DELTA = 0x9e3779b9
TEA_KEY = [0x12345678, 0x3456789a, 0x89abcdef, 0x12345678]
TARGET_WORDS = [0xa92f3865, 0x9e60e953]
TABLE_TARGET = bytes.fromhex(
    "d4 59 23 76 b4 bf e3 2c 58 8f 56 19 da f0 c0 bd "
    "36 3d 7b 46 1b b8 17 1f e3 d0 03 45 cd 04 ed c9 "
    "67 e6 ab 29 a7 bc 0b de 5c 30 71 d7 d5 5a c6 9f "
    "40 65 c4 71 a9 c3 ae d9 b5 e5 12 8c 80 52 34 36"
)
ENCODED_TARGET = "0tCPwtnncFZyYUlSK/4Cw0/echcG2lteBWnG2Ulw0htCYTMW"

def mix(v, total, ka, kb):
    return ((((v << 4) & MASK) + ka) & MASK) ^ ((v + total) & MASK) ^ (((v >> 5) + kb) & MASK)

def xtea_encrypt(v0, v1):
    total = 0
    for _ in range(32):
        total = (total + DELTA) & MASK
        v0 = (v0 + mix(v1, total, TEA_KEY[0], TEA_KEY[1])) & MASK
        v1 = (v1 + mix(v0, total, TEA_KEY[2], TEA_KEY[3])) & MASK
    return v0, v1

def xtea_decrypt(v0, v1):
    total = (DELTA * 32) & MASK
    for _ in range(32):
        v1 = (v1 - mix(v0, total, TEA_KEY[2], TEA_KEY[3])) & MASK
        v0 = (v0 - mix(v1, total, TEA_KEY[0], TEA_KEY[1])) & MASK
        total = (total - DELTA) & MASK
    return v0, v1

plain_words = xtea_decrypt(*TARGET_WORDS)
input_key = b"".join(w.to_bytes(4, "little") for w in plain_words)
print("XTEA target words:", [f"0x{x:08x}" for x in TARGET_WORDS])
print("XTEA recovered input words:", [f"0x{x:08x}" for x in plain_words])
print("First-level input bytes:", input_key.hex(), repr(input_key))
print("Forward XTEA verification:", [f"0x{x:08x}" for x in xtea_encrypt(*plain_words)])
assert xtea_encrypt(*plain_words) == tuple(TARGET_WORDS)
assert len(TABLE_TARGET) == 64

# Reproduce the second-level RC4-like transformation seen in the binary.
state = list(range(256))
key_schedule = [input_key[i % len(input_key)] for i in range(256)]
j = 0
for i in range(256):
    j = (j + state[i] + key_schedule[i]) & 0xff
    state[i], state[j] = state[j], state[i]
i = 0
j = 0
stream = []
for _ in range(64):
    i = (i + 1) & 0xff
    j = (j + state[i]) & 0xff
    state[i], state[j] = state[j], state[i]
    stream.append(state[(state[i] + state[j]) & 0xff])
raw_table = bytes((cipher - ks) & 0xff for cipher, ks in zip(TABLE_TARGET, stream))
forward_table = bytes((plain + ks) & 0xff for plain, ks in zip(raw_table, stream))
print("RC4-like keystream:", bytes(stream).hex())
print("Recovered 64-byte raw table hex:", raw_table.hex())
print("Recovered raw table repr:", repr(raw_table))
print("Recovered raw table ASCII:", raw_table.decode("ascii", errors="backslashreplace"))
print("All raw table bytes printable ASCII:", all(0x21 <= c <= 0x7e for c in raw_table))
print("Raw table byte uniqueness:", len(set(raw_table)), "distinct values of", len(raw_table))
print("RC4-like forward verification exact:", forward_table == TABLE_TARGET)
assert forward_table == TABLE_TARGET

alphabet = raw_table[1:33]
print("Base32 alphabet used by code (raw_table[1:33]):", repr(alphabet))
print("Alphabet length and uniqueness:", len(alphabet), len(set(alphabet)))
assert len(alphabet) == 32
assert len(set(alphabet)) == 32

def decode_base32_custom(encoded, alpha):
    inverse = {ch: i for i, ch in enumerate(alpha)}
    if any(ord(ch) not in inverse for ch in encoded):
        raise ValueError("encoded target contains symbol outside recovered alphabet")
    out = bytearray()
    groups = [encoded[k:k+8] for k in range(0, len(encoded), 8)]
    for group in groups:
        if len(group) != 8:
            raise ValueError("incomplete Base32 group")
        value = 0
        for ch in group:
            value = (value << 5) | inverse[ord(ch)]
        out.extend(value.to_bytes(5, "big"))
    return bytes(out)

decoded = decode_base32_custom(ENCODED_TARGET, alphabet)
print("Encoded target length:", len(ENCODED_TARGET))
print("Decoded full target bytes length:", len(decoded))
print("Decoded full target bytes hex:", decoded.hex())
print("Decoded full target bytes repr:", repr(decoded))
print("Decoded visible ASCII:", decoded.decode("ascii", errors="backslashreplace"))
print("Decoded minus final zero (if present):", repr(decoded[:-1]) if decoded.endswith(b"\x00") else "final byte is nonzero")
print("Encoded first 30 symbols (actual comparator length):", ENCODED_TARGET[:30])
print("Flag-format check:", decoded.startswith(b"flag{") and b"}" in decoded)

def encode_base32_custom(data, alpha):
    out = []
    for offset in range(0, len(data), 5):
        chunk = data[offset:offset+5].ljust(5, b"\x00")
        value = int.from_bytes(chunk, "big")
        for shift in (35, 30, 25, 20, 15, 10, 5, 0):
            out.append(alpha[(value >> shift) & 0x1f])
    return bytes(out).decode("ascii")

forward_encoded = encode_base32_custom(decoded, alphabet)
print("Recovered candidate flag length:", len(decoded))
print("Recovered candidate flag:", decoded.decode("ascii"))
print("Base32 forward encoding:", forward_encoded)
print("Full 48-symbol forward round-trip exact:", forward_encoded == ENCODED_TARGET)
assert forward_encoded == ENCODED_TARGET
