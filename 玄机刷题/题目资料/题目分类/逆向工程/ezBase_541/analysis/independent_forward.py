"""Independent byte-level forward check derived from the disassembled encoder."""
from pathlib import Path

image = (Path(__file__).parent / "upx0_patched.bin").read_bytes()
candidate = b"flag{Y0u_@R3_Upx_4nd_b45364_m4st3r!}"
alphabet = image[0x3040:image.index(0, 0x3040)]
target = image[0x3000:image.index(0, 0x3000)]

# fgets receives an Enter-terminated line; strcspn(buffer, "\n") puts NUL
# at LF, so the supplied flag bytes are the encoder's exact input.
stdin_line = candidate + bytes([10])
input_bytes = stdin_line.split(bytes([10]), 1)[0]

# Directly model the assembly: pack up to three bytes into 24 bits, extract
# four 6-bit indexes, use '=' only for missing source bytes, then XOR every
# non-'=' output byte with 0x04.
raw = bytearray()
for off in range(0, len(input_bytes), 3):
    block = input_bytes[off:off + 3]
    packed = block[0] << 16
    if len(block) > 1:
        packed |= block[1] << 8
    if len(block) > 2:
        packed |= block[2]
    raw.append(alphabet[(packed >> 18) & 0x3f])
    raw.append(alphabet[(packed >> 12) & 0x3f])
    raw.append(alphabet[(packed >> 6) & 0x3f] if len(block) > 1 else ord("="))
    raw.append(alphabet[packed & 0x3f] if len(block) > 2 else ord("="))

raw_encoded = bytes(raw)
transformed = bytes(ch if ch == ord("=") else ch ^ 0x04 for ch in raw_encoded)

print(f"candidate={candidate.decode('ascii')}")
print(f"candidate_len={len(candidate)} stdin_line_hex={(candidate + bytes([10])).hex()}")
print(f"strcspn_LF_input_len={len(input_bytes)} input_hex={input_bytes.hex()}")
print(f"alphabet_len={len(alphabet)} alphabet={alphabet.decode('ascii')}")
print(f"pre_xor_len={len(raw_encoded)} pre_xor={raw_encoded.decode('ascii')}")
print(f"post_xor_len={len(transformed)} post_xor={transformed.decode('ascii')}")
print(f"target_len={len(target)} target={target.decode('ascii')}")
print(f"byte_match={transformed == target}")
print(f"first_mismatch={next((i for i, (a, b) in enumerate(zip(transformed, target)) if a != b), None)}")
print(f"final_raw_byte={raw_encoded[-1]:#04x} final_target_byte={target[-1]:#04x}")
print(f"no_padding_for_36_bytes={len(input_bytes) % 3 == 0 and b'=' not in raw_encoded}")
