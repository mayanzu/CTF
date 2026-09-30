import base64
import hashlib
from pathlib import Path

TARGET = b"iP}ui7siC`otMgA~h5o]Tg<4jPmtIvM5C~I4h644K7M~KVg="
CUSTOM = b"AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789+/"
STANDARD = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# The binary XORs each encoded byte except a real Base64 padding byte.
# Therefore reverse XOR on every ciphertext byte first: the last '=' becomes '9'.
pre_xor = bytes(byte ^ 0x04 for byte in TARGET)
assert all(byte in CUSTOM for byte in pre_xor), "reversed bytes are outside the custom alphabet"
canonical = bytes(STANDARD[CUSTOM.index(byte)] for byte in pre_xor)
flag = base64.b64decode(canonical, validate=True)

# Reproduce the target program: standard Base64, custom alphabet substitution,
# then XOR 0x04 on every output byte except actual '=' padding.
standard_encoded = base64.b64encode(flag)
custom_encoded = bytes(
    byte if byte == ord("=") else CUSTOM[STANDARD.index(byte)]
    for byte in standard_encoded
)
program_output = bytes(
    byte if byte == ord("=") else byte ^ 0x04
    for byte in custom_encoded
)

print(f"target_len={len(TARGET)} target={TARGET.decode('ascii')}")
print(f"xor4_reversed={pre_xor.decode('ascii')}")
print(f"custom_alphabet_mapped_to_standard={canonical.decode('ascii')}")
print(f"decoded_len={len(flag)} decoded_flag={flag.decode('ascii')}")
print(f"standard_base64={standard_encoded.decode('ascii')}")
print(f"custom_base64={custom_encoded.decode('ascii')}")
print(f"program_output={program_output.decode('ascii')}")
print(f"roundtrip_exact={program_output == TARGET}")
print(f"flag_sha256={hashlib.sha256(flag).hexdigest()}")
print(f"binary_sha256={hashlib.sha256(Path(__file__).with_name('ezBase').joinpath('ezre.exe').read_bytes()).hexdigest()}")
assert len(flag) == 36
assert program_output == TARGET
