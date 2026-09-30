import struct

DELTA = 0x9E3779B9
MASK = 0xFFFFFFFF
cipher = [0x3E49206C, 0x0F9E2FC8, 0xBCD2D413, 0x45E6B5FA, 0x7FFB1950, 0x5C649DF2, 0xAC3CBF0D, 0x8FB10FD6, 0x23BE7E15, 0x6419A002, 0x0838431A]
key = [0x12345678, 0x9ABCDEF0, 0xFEDCBA98, 0x87654321]

def mx(z, y, total, key_word):
    return (((z >> 5 ^ (y << 2 & MASK)) + (y >> 3 ^ (z << 4 & MASK))) ^ ((total ^ y) + (key_word ^ z))) & MASK

def encrypt(v):
    v = v[:]
    n = len(v)
    rounds = 6 + 52 // n
    total = 0
    z = v[-1]
    for _ in range(rounds):
        total = (total + DELTA) & MASK
        e = (total >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            v[p] = (v[p] + mx(z, y, total, key[(p & 3) ^ e])) & MASK
            z = v[p]
        y = v[0]
        p = n - 1
        v[p] = (v[p] + mx(z, y, total, key[(p & 3) ^ e])) & MASK
        z = v[p]
    return v

def decrypt(v):
    v = v[:]
    n = len(v)
    rounds = 6 + 52 // n
    total = (rounds * DELTA) & MASK
    y = v[0]
    for _ in range(rounds):
        e = (total >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - mx(z, y, total, key[(p & 3) ^ e])) & MASK
            y = v[p]
        z = v[n - 1]
        p = 0
        v[0] = (v[0] - mx(z, y, total, key[(p & 3) ^ e])) & MASK
        y = v[0]
        total = (total - DELTA) & MASK
    return v

plain_words = decrypt(cipher)
plain = b''.join(struct.pack('<I', word) for word in plain_words)
print('words =', len(cipher), 'rounds =', 6 + 52 // len(cipher), 'expected sum =', hex((6 + 52 // len(cipher)) * DELTA & MASK))
print('decrypted words =', [f'{word:08x}' for word in plain_words])
print('candidate bytes =', plain.hex())
print('candidate text =', plain.decode('ascii', errors='replace'))
print('length =', len(plain), 'all printable =', all(0x20 <= b <= 0x7e for b in plain))
print('reencryption matches target =', encrypt(plain_words) == cipher)
