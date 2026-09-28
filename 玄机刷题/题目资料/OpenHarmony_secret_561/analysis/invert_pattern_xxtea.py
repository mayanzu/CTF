MASK = 0xffffffff
DELTA = 0x9e3779b9
KEY = [11, 45, 14, 114514]
TARGET = [0xe52bcc34, 0x344e3b05, 0xded45d41, 0x5f1ed75a, 0x97439820, 0x1f1b5b18, 0xf108fe7f, 0x93962769, 0xc4b198ca]

def mx(y, z, p, e, total):
    left = (((z >> 5) ^ ((y << 2) & MASK)) + ((y >> 3) ^ ((z << 4) & MASK))) & MASK
    right = ((total ^ y) + (KEY[(p & 3) ^ e] ^ z)) & MASK
    return left ^ right

def encrypt(v):
    v = list(v)
    n = len(v)
    total = 0
    rounds = 6 + 52 // n
    z = v[-1]
    for _ in range(rounds):
        total = (total + DELTA) & MASK
        e = (total >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            v[p] = (v[p] + mx(y, z, p, e, total)) & MASK
            z = v[p]
        p = n - 1
        y = v[0]
        v[p] = (v[p] + mx(y, z, p, e, total)) & MASK
        z = v[p]
    return v

def decrypt(v):
    v = list(v)
    n = len(v)
    rounds = 6 + 52 // n
    total = (rounds * DELTA) & MASK
    y = v[0]
    while total:
        e = (total >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - mx(y, z, p, e, total)) & MASK
            y = v[p]
        p = 0
        z = v[n - 1]
        v[0] = (v[0] - mx(y, z, p, e, total)) & MASK
        y = v[0]
        total = (total - DELTA) & MASK
    return v

plain = decrypt(TARGET)
print('rounds:', 6 + 52 // len(TARGET))
print('target:', ' '.join(f'{x:08x}' for x in TARGET))
print('candidate words unsigned:', plain)
print('candidate words hex:', ' '.join(f'{x:08x}' for x in plain))
print('candidate words signed:', [x if x < 0x80000000 else x - 0x100000000 for x in plain])
print('forward round-trip matches target:', encrypt(plain) == TARGET)
print('candidate little-endian bytes:', bytes().join(x.to_bytes(4, 'little') for x in plain).hex())
print('candidate big-endian bytes:', bytes().join(x.to_bytes(4, 'big') for x in plain).hex())
