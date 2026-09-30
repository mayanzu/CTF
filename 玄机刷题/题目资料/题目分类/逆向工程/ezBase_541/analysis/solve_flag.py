"""Invert and forward-check the statically recovered custom Base64 transform."""
from pathlib import Path

image = Path(__file__).with_name("upx0_patched.bin").read_bytes()
expected = image[0x3000:image.index(0, 0x3000)]
alphabet = image[0x3040:image.index(0, 0x3040)]
assert len(expected) == 48, f"unexpected target length: {len(expected)}"
assert len(alphabet) == 64, f"unexpected alphabet length: {len(alphabet)}"

lookup = {ch: i for i, ch in enumerate(alphabet)}
def decode_custom(encoded):
    decoded = bytearray()
    for pos in range(0, len(encoded), 4):
        quad = encoded[pos:pos+4]
        vals = [lookup[ch] if ch != ord("=") else 0 for ch in quad]
        decoded.append((vals[0] << 2) | (vals[1] >> 4))
        if quad[2] != ord("="):
            decoded.append(((vals[1] & 0x0F) << 4) | (vals[2] >> 2))
        if quad[3] != ord("="):
            decoded.append(((vals[2] & 0x03) << 6) | vals[3])
    return decoded

def encode_custom(raw):
    result = bytearray()
    for pos in range(0, len(raw), 3):
        block = raw[pos:pos+3]
        n = int.from_bytes(block + b"\0" * (3-len(block)), "big")
        chars = [alphabet[(n >> 18) & 63], alphabet[(n >> 12) & 63]]
        chars.append(alphabet[(n >> 6) & 63] if len(block) > 1 else ord("="))
        chars.append(alphabet[n & 63] if len(block) > 2 else ord("="))
        result.extend(ch if ch == ord("=") else ch ^ 4 for ch in chars)
    return bytes(result)

print(f"expected_transform={expected.decode('ascii')}")
print(f"recovered_alphabet={alphabet.decode('ascii')}")
for mode in ("padding", "xor-to-equals"):
    # XOR is skipped only when the *pre-XOR* character equals '='. A target '='
    # can therefore also be a normal alphabet '9' XOR 4; test both cases.
    encoded = bytearray(ch if ch == ord("=") else ch ^ 4 for ch in expected)
    if mode == "xor-to-equals" and expected[-1] == ord("="):
        encoded[-1] = ord("=") ^ 4
    if not all(ch in alphabet or ch == ord("=") for ch in encoded):
        print(f"mode={mode}: invalid alphabet character")
        continue
    decoded = decode_custom(encoded)
    forward = encode_custom(decoded)
    print(f"mode={mode} pre_xor_base64={encoded.decode('ascii')}")
    print(f"mode={mode} decoded_len={len(decoded)} candidate_hex={decoded.hex()}")
    print(f"mode={mode} candidate_repr={decoded!r}")
    print(f"mode={mode} forward_check={forward.decode('ascii')} match={forward == expected}")
    if forward == expected:
        print(f"VERIFIED_CANDIDATE={decoded.decode('ascii')}")
