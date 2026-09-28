import base64, hashlib
from pathlib import Path

target = b"iP}ui7siC`otMgA~h5o]Tg<4jPmtIvM5C~I4h644K7M~KVg="
alphabet = b"AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789+/"
# Undo the encoder's final bytewise XOR (except the Base64 padding character).
plain_b64 = bytes((ch ^ 0x04) if ch != ord('=') else ch for ch in target)
print(f"target_len={len(target)}")
print(f"target={target.decode('ascii')}")
print(f"xor4_reversed={plain_b64.decode('ascii')}")
print(f"alphabet_len={len(alphabet)} alphabet_unique={len(set(alphabet))}")
assert len(alphabet) == 64 and len(set(alphabet)) == 64
assert all(ch == ord('=') or ch in alphabet for ch in plain_b64)
# Convert custom alphabet symbols back to canonical Base64 symbols.
canon = bytes((ord('=') if ch == ord('=') else ord('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ '[alphabet.index(ch)])) for ch in plain_b64)
print(f"canonical_b64={canon.decode('ascii')}")
candidate = base64.b64decode(canon, validate=True)
print(f"candidate_len={len(candidate)}")
print(f"candidate_ascii={candidate.decode('ascii')}")
print(f"candidate_hex={candidate.hex()}")
# Exact forward reproduction from the recovered input.
enc = base64.b64encode(candidate)
custom = bytes(alphabet[ord("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i])] if c != ord('=') else c for c in enc for i in [0])
# Re-map each canonical Base64 byte while preserving padding.
custom = bytes(ord('=') if c == ord('=') else alphabet[b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".index(c)] for c in enc)
reproduced = bytes((c ^ 4) if c != ord('=') else c for c in custom)
print(f"roundtrip_match={reproduced == target}")
print(f"candidate_sha256={hashlib.sha256(candidate).hexdigest()}")
assert len(candidate) == 36 and reproduced == target
input_path = Path(__file__).resolve().parent / "candidate_input.txt"
input_path.write_bytes(candidate + b"\n")
print(f"input_file={input_path}")
print(f"input_file_len={input_path.stat().st_size}")
