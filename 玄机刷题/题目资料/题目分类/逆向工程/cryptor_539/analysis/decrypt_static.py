import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = b"EzCrypt0ofPython"
iv = b"1145140A01919810"
ct = base64.b64decode("WegWMtim1YwucYelL2g+DU2x/B/VsQrFz2pNMJy95rE=")
print("key_len =", len(key))
print("iv_len =", len(iv))
print("ciphertext_len =", len(ct))
for name, cipher in (
    ("AES-CBC", AES.new(key, AES.MODE_CBC, iv)),
    ("AES-ECB", AES.new(key, AES.MODE_ECB)),
):
    raw = cipher.decrypt(ct)
    print(name, "raw =", repr(raw))
    for pad in ("PKCS7", "zero", "none"):
        if pad == "PKCS7":
            try:
                pt = unpad(raw, AES.block_size)
            except ValueError:
                continue
        elif pad == "zero":
            pt = raw.rstrip(b"\x00")
        else:
            pt = raw
        try:
            decoded = pt.decode("utf-8")
        except UnicodeDecodeError:
            decoded = "<not UTF-8>"
        print(name, pad, "plaintext =", repr(pt), "text =", repr(decoded))
