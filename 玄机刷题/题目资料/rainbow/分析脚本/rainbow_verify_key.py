from pathlib import Path
import re,struct
root=Path(__file__).resolve().parents[1]
exe=(root/'附件'/'rainbow').read_bytes()
# Recover the byte string written by hide_flag's little-endian immediates.
buf=bytearray(24)
buf[0:8]=struct.pack('<Q',0x6968747b67616c66)
buf[8:16]=struct.pack('<Q',0x616c665f73695f73)
buf[15:19]=struct.pack('<I',0x007d6761) # starts one byte before the second qword ends
embedded=bytes(buf).split(b'\0',1)[0]
print('embedded plaintext recovered from hide_flag constants:',embedded.decode('ascii'))
print('embedded length:',len(embedded))
embedded_cipher=bytes(c^0x5a for c in embedded)
print('hide_flag key immediate:',hex(0x5a))
print('embedded ciphertext:',embedded_cipher.hex().upper())
text=(root/'附件'/'output.txt').read_text(encoding='ascii').strip()
external=bytes.fromhex(text.split(':',1)[1].strip())
plain=bytes(c^0x5a for c in external)
print('external ciphertext length:',len(external))
print('external plaintext:',plain.decode('ascii'))
print('external starts with flag prefix:',plain.startswith(b'flag{'))
print('external closes with brace:',plain.endswith(b'}'))
print('external body all alphanumeric:',bool(re.fullmatch(rb'[A-Za-z0-9]+',plain[5:-1])))
print('external payload differs from embedded hide_flag ciphertext:',external!=embedded_cipher)
