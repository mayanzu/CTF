from pathlib import Path
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

analysis = Path(__file__).resolve().parent
listing = (analysis / '538_objdump_main.txt').read_text(encoding='utf-8-sig', errors='replace')
values = {}
for line in listing.splitlines():
    m = re.search(r'/[rbp\+0x([0-9a-fA-F]+)/],0x([0-9a-fA-F]+)', line)
    if m:
        offset, value = (int(m.group(1), 16), int(m.group(2), 16))
        values[offset] = value
ciphertext = bytes(values[offset] for offset in range(0xA0, 0xC0))
key = bytes(values[offset] for offset in range(0xC0, 0xD0))
assert len(ciphertext) == 32 and len(key) == 16, (len(ciphertext), len(key))
decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()
encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
roundtrip = encryptor.update(plaintext) + encryptor.finalize()
print(f'KEY_HEX={key.hex()}')
print(f'KEY_ASCII={key.decode("ascii")}')
print(f'CIPHERTEXT_HEX={ciphertext.hex()}')
print(f'PLAINTEXT_HEX={plaintext.hex()}')
print(f'PLAINTEXT_ASCII={plaintext.decode("ascii")}')
print(f'PLAINTEXT_LEN={len(plaintext)}')
print(f'REENCRYPT_HEX={roundtrip.hex()}')
print(f'ROUNDTRIP_MATCH={roundtrip == ciphertext}')
print(f'FLAG_SHAPE={plaintext.startswith(b"flag{") and plaintext.endswith(b"}")}')
