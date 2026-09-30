import base64
import subprocess
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = b"EzCrypt0ofPython"
iv = b"1145140A01919810"
encoded = b"WegWMtim1YwucYelL2g+DU2x/B/VsQrFz2pNMJy95rE="
ciphertext = base64.b64decode(encoded)
decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()
flag_bytes = plaintext.rstrip(b"\x00")
flag = flag_bytes.decode("ascii")
print("cryptography ciphertext bytes:", len(ciphertext))
print("cryptography raw plaintext hex:", plaintext.hex())
print("cryptography raw plaintext repr:", repr(plaintext))
print("cryptography stripped flag:", flag)
print("cryptography padding suffix:", len(plaintext) - len(flag_bytes), "NUL bytes")
assert plaintext == flag_bytes + b"\x00" * 5
assert flag.startswith("flag{") and flag.endswith("}")
proc = subprocess.run(
    ["openssl", "enc", "-d", "-aes-128-cbc", "-K", key.hex(), "-iv", iv.hex(), "-nopad", "-base64"],
    input=encoded + b"\n",
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=True,
)
print("OpenSSL raw plaintext hex:", proc.stdout.hex())
print("OpenSSL raw plaintext repr:", repr(proc.stdout))
print("Independent implementations agree:", proc.stdout == plaintext)
assert proc.stdout == plaintext
