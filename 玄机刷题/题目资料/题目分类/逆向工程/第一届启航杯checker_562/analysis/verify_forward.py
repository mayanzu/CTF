from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parent.parent
EXE = ROOT / "analysis" / "extracted" / "checker.exe"
candidate = b"flag{enp17I4p8TZmAriao2lq5tAArZ2P1wxBUwXU2}"
expected_cipher = bytes.fromhex("454f424458464d5312146a17531b77794e62514a424c114f52165762625179117312545b6176547b76115e")
image = EXE.read_bytes()
# Independent cross-check: values are pinned from the disassembly and .data hexdump.
cipher_from_file = image[0x3220:0x3220 + 43]
forward = bytes(byte ^ 0x23 for byte in candidate)
print("checker.exe SHA256:", hashlib.sha256(image).hexdigest().upper())
print("candidate literal:", candidate.decode("ascii"))
print("candidate length:", len(candidate))
print("expected ciphertext:", expected_cipher.hex())
print("ciphertext at .data+0x20:", cipher_from_file.hex())
print("forward XOR result:", forward.hex())
print("literal cipher equals file bytes:", expected_cipher == cipher_from_file)
print("forward output equals complete stored bytes:", forward == cipher_from_file)
print("NUL-terminated strcmp operands equal:", forward + b"\0" == cipher_from_file + b"\0")
assert len(candidate) == 43
assert candidate.startswith(b"flag{") and candidate.endswith(b"}")
assert expected_cipher == cipher_from_file
assert forward == cipher_from_file
assert forward + b"\0" == cipher_from_file + b"\0"
print("RESULT: independent byte-for-byte forward check passed; checker.exe was not executed.")
