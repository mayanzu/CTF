"""Independent forward-only verifier for an explicit #541 candidate.

It reads only the fresh static reconstruction produced from the original PE;
it does not import or call the inversion/decompression code.
"""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: verify_candidate_541.py CANDIDATE")
image_path = Path(__file__).with_name("rederived_541_patched.bin")
image = image_path.read_bytes()
candidate = sys.argv[1].encode("ascii")

def cstr(offset):
    end = image.index(0, offset)
    return image[offset:end]

target = cstr(0x3000)
alphabet = cstr(0x3040)
# Confirm the control-flow/data references from raw instruction bytes.
length_gate = bytes.fromhex("48 83 7c 24 30 24")
xor_compare = bytes.fromhex("83 f8 3d")
xor_imm = bytes.fromhex("83 f1 04")
target_lea = bytes.fromhex("48 8d 15 2e 2f 00 00")
alphabet_lea = bytes.fromhex("48 8d 05 19 2e 00 00")
assert image[0x89:0x8f] == length_gate, image[0x89:0x8f].hex()
assert image[0x359:0x35c] == xor_compare, image[0x359:0x35c].hex()
assert image[0x36a:0x36d] == xor_imm, image[0x36a:0x36d].hex()
assert image[0xcb:0xd2] == target_lea, image[0xcb:0xd2].hex()
assert image[0x220:0x227] == alphabet_lea, image[0x220:0x227].hex()
target_ref = (0x1000 + 0xcb + 7 + int.from_bytes(image[0xce:0xd2], "little", signed=True))
alphabet_ref = (0x1000 + 0x220 + 7 + int.from_bytes(image[0x223:0x227], "little", signed=True))
assert target_ref == 0x4000 and alphabet_ref == 0x4040, (hex(target_ref),hex(alphabet_ref))

# fgets receives an Enter-terminated line; strcspn(buffer, "\\n") cuts at LF.
stdin_line = candidate + b"\n"
input_bytes = stdin_line.split(b"\n", 1)[0]
assert len(input_bytes) == 0x24, f"length gate rejected: {len(input_bytes)} != 36"
assert len(target) == 48 and len(alphabet) == 64
assert len(set(alphabet)) == 64

# Independently simulate the three-byte to four-symbol routine and its XOR loop.
raw = bytearray()
for pos in range(0, len(input_bytes), 3):
    block = input_bytes[pos:pos + 3]
    assert len(block) == 3, "36-byte gate must leave only complete triples"
    packed = (block[0] << 16) | (block[1] << 8) | block[2]
    raw.extend((alphabet[(packed >> 18) & 63], alphabet[(packed >> 12) & 63],
                alphabet[(packed >> 6) & 63], alphabet[packed & 63]))
post_xor = bytes(ch if ch == 0x3d else ch ^ 0x04 for ch in raw)
print(f"candidate={candidate.decode('ascii')}")
print(f"candidate_hex={candidate.hex()}")
print(f"line_input_len_after_LF_cut={len(input_bytes)} length_gate_0x24=True")
print(f"alphabet={alphabet.decode('ascii')} alphabet_bytes={len(alphabet)}")
print(f"forward_pre_xor={raw.decode('ascii')} bytes={len(raw)} padding_bytes={raw.count(0x3d)}")
print(f"forward_post_xor={post_xor.decode('ascii')} bytes={len(post_xor)}")
print(f"embedded_target={target.decode('ascii')} bytes={len(target)}")
print(f"exact_byte_match={post_xor == target}")
print(f"mismatch_offsets={[i for i,(a,b) in enumerate(zip(post_xor,target)) if a != b]}")
print(f"final_pre_xor_byte=0x{raw[-1]:02x} final_target_byte=0x{target[-1]:02x}")
if post_xor != target:
    raise SystemExit("candidate does not satisfy the embedded comparison")
