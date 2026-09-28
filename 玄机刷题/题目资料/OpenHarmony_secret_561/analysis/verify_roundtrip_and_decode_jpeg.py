import base64
import hashlib
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import decrypt_enc_custom_sm4 as cipher_impl

cipher = cipher_impl.cipher
plain = cipher_impl.plain
rk = cipher_impl.rk
checks = [cipher_impl.encrypt_block(plain[i:i+16], rk) == cipher[i:i+16] for i in range(0, len(cipher), 16)]
print('block count:', len(checks))
print('all blocks re-encrypt exactly to decoded resource ciphertext:', all(checks))
print('mismatch block indexes:', [i for i, ok in enumerate(checks) if not ok][:20])
print('decrypted tail bytes/repr:', plain[-32:].hex(), repr(plain[-32:]))
padding = plain[-1]
assert 1 <= padding <= 16 and plain[-padding:] == bytes([padding]) * padding
unpadded = plain[:-padding]
print('PKCS#7 padding length and exact-byte validation:', padding, True)
print('unpadded Base64 length:', len(unpadded), 'mod4:', len(unpadded) % 4)
image = base64.b64decode(unpadded, validate=True)
out = cipher_impl.ROOT / 'analysis/enc.recovered.jpg'
out.write_bytes(image)
print('decoded JPEG bytes:', len(image))
print('decoded JPEG SHA256:', hashlib.sha256(image).hexdigest())
print('JPEG magic:', image[:16].hex())
print('JPEG output:', out)
