import base64
import hashlib
import pathlib
import struct

ROOT = pathlib.Path('/mnt/c/Users/mzj/Desktop/CTF/玄机刷题/题目资料/OpenHarmony_secret_561')
LIB = ROOT / 'hap_contents/libs/x86_64/libsecret.so'
ENC = ROOT / 'hap_contents/resources/rawfile/enc'
OUT = ROOT / 'analysis/enc.custom-sm4-decrypted.bin'
MASK = 0xffffffff
DELTA = 0x9e3779b9
FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
KEY = [0xe52bcc34, 0x1f1b5b18, 0x5f1ed75a, 0xf108fe7f]

lib = LIB.read_bytes()
sbox = list(lib[0x44e0:0x45e0])
ck = [int.from_bytes(lib[0x45e0 + 8*i:0x45e0 + 8*i + 4], 'little') for i in range(32)]
assert len(sbox) == 256 and len(ck) == 32

def rol(x, n):
    x &= MASK
    return ((x << n) | (x >> (32 - n))) & MASK

def tau(x):
    return ((sbox[(x >> 24) & 255] << 24) |
            (sbox[(x >> 16) & 255] << 16) |
            (sbox[(x >> 8) & 255] << 8) |
            sbox[x & 255])

def l2(x):
    return x ^ rol(x, 13) ^ rol(x, 23)

def l1(x):
    return x ^ rol(x, 2) ^ rol(x, 10) ^ rol(x, 18) ^ rol(x, 24)

def make_rk(key):
    state = [(key[i] ^ FK[i]) & MASK for i in range(4)]
    rk = []
    for i in range(32):
        j = i & 3
        mix = state[(i+2)&3] ^ state[(i+1)&3] ^ state[(i-1)&3] ^ ck[i]
        nxt = state[j] ^ l2(tau(mix))
        state[j] = nxt & MASK
        rk.append(nxt & MASK)
    return rk

def round_f(a, b, c, rk):
    return (l1(tau((a ^ b ^ c ^ rk) & MASK)) ^ DELTA) & MASK

def encrypt_block(block, rk):
    x = list(struct.unpack('>4I', block))
    for i in range(32):
        j = i & 3
        x[j] = (x[j] ^ round_f(x[(i+1)&3], x[(i+2)&3], x[(i+3)&3], rk[i])) & MASK
    return struct.pack('>4I', *reversed(x))

def decrypt_block(block, rk):
    x = list(reversed(struct.unpack('>4I', block)))
    for i in range(31, -1, -1):
        j = i & 3
        x[j] = (x[j] ^ round_f(x[(i+1)&3], x[(i+2)&3], x[(i+3)&3], rk[i])) & MASK
    return struct.pack('>4I', *x)

rk = make_rk(KEY)
test = bytes(range(16))
test_enc = encrypt_block(test, rk)
print('SM4-like custom schedule source: native .rodata S-box @0x44e0, CK @0x45e0')
print('S-box head/tail:', bytes(sbox[:8]).hex(), bytes(sbox[-8:]).hex())
print('CK head/tail:', [f'{x:08x}' for x in ck[:4]], [f'{x:08x}' for x in ck[-4:]])
print('key words:', [f'{x:08x}' for x in KEY])
print('round key first/last:', [f'{x:08x}' for x in rk[:4]], [f'{x:08x}' for x in rk[-4:]])
print('internal block round-trip:', decrypt_block(test_enc, rk) == test)
print('test block/cipher:', test.hex(), test_enc.hex())
raw_b64 = ENC.read_bytes()
cipher = base64.b64decode(raw_b64, validate=True)
print('enc ASCII length/SHA256:', len(raw_b64), hashlib.sha256(raw_b64).hexdigest())
print('decoded ciphertext length/SHA256:', len(cipher), hashlib.sha256(cipher).hexdigest())
print('block aligned:', len(cipher) % 16 == 0)
plain = b''.join(decrypt_block(cipher[i:i+16], rk) for i in range(0, len(cipher), 16))
OUT.write_bytes(plain)
print('decrypted length/SHA256:', len(plain), hashlib.sha256(plain).hexdigest())
print('first 96 plaintext bytes:', plain[:96].hex())
print('first 96 plaintext repr:', repr(plain[:96]))
print('printable ASCII ratio:', sum(32 <= b < 127 or b in (9,10,13) for b in plain) / len(plain))
print('first-block re-encryption matches input:', encrypt_block(plain[:16], rk) == cipher[:16])
print('output path:', OUT)
