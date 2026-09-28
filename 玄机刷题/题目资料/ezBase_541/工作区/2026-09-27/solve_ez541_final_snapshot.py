import base64, hashlib
from pathlib import Path

target = b"iP}ui7siC`otMgA~h5o]Tg<4jPmtIvM5C~I4h644K7M~KVg="
alphabet = b"AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789+/"
canonical_alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
plain_b64 = bytes((ch ^ 4) if ch != ord('=') else ch for ch in target)
canonical = bytes(ord('=') if ch == ord('=') else canonical_alphabet[alphabet.index(ch)] for ch in plain_b64)
candidate = base64.b64decode(canonical, validate=True)
roundtrip = base64.b64encode(candidate)
custom = bytes(ord('=') if ch == ord('=') else alphabet[canonical_alphabet.index(ch)] for ch in roundtrip)
reproduced = bytes((ch ^ 4) if ch != ord('=') else ch for ch in custom)
print(f"target_len={len(target)} target={target.decode()}")
print(f"xor4_reversed={plain_b64.decode()}")
print(f"canonical_b64={canonical.decode()}")
print(f"decoded_len={len(candidate)} decoded_ascii={candidate.decode()}")
print(f"encoder_roundtrip_b64={roundtrip.decode()}")
print(f"target_roundtrip_match={reproduced == target}")
print(f"roundtrip_diff_indices={[i for i,(x,y) in enumerate(zip(reproduced,target)) if x!=y]}")
print(f"candidate_sha256={hashlib.sha256(candidate).hexdigest()}")
output_dir = Path(__file__).resolve().parent
(output_dir / "candidate_35byte_prefix.txt").write_bytes(candidate+b"\n")
(output_dir / "candidate_36byte_flag.txt").write_bytes(candidate+b"}"+b"\n")
