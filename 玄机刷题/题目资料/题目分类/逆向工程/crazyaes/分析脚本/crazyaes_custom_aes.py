from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CIPHERTEXT = bytes.fromhex('B43836301E6848575101B7039B98E37E')
ROUND_MASK = bytes.fromhex('00 01 02 03 01 00 03 02 02 03 00 01 03 02 01 00')
KEYS = {
    'no_debugger_h_mutation': b'gah43jJKgfjGMeAR',
    'debugger_present_original': b'ga!43jJKgfjGMeAR',
}


def gf_mul(a, b):
    out = 0
    for _ in range(8):
        if b & 1:
            out ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return out


def rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def gf_pow(a, n):
    out = 1
    while n:
        if n & 1:
            out = gf_mul(out, a)
        a = gf_mul(a, a)
        n >>= 1
    return out


def sbox(x):
    inv = 0 if x == 0 else gf_pow(x, 254)
    return inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63

S = [sbox(i) for i in range(256)]
IS = [0] * 256
for i, v in enumerate(S):
    IS[v] = i


def expand_key(key):
    words = [list(key[i:i+4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        temp = words[i - 1][:]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [S[x] for x in temp]
            temp[0] ^= rcon
            rcon = gf_mul(rcon, 2)
        words.append([words[i - 4][j] ^ temp[j] for j in range(4)])
    return [sum(words[4*r:4*r+4], []) for r in range(11)]


def add_key(state, key):
    return [a ^ b for a, b in zip(state, key)]


def xor_round_mask(state):
    return [a ^ b for a, b in zip(state, ROUND_MASK)]


def shift_rows(state):
    return [state[4*((c+r) % 4)+r] for c in range(4) for r in range(4)]


def inv_shift_rows(state):
    return [state[4*((c-r) % 4)+r] for c in range(4) for r in range(4)]


def mix_columns(state, mask=0):
    out = [0] * 16
    for c in range(4):
        a = state[4*c:4*c+4]
        out[4*c+0] = gf_mul(a[0],2) ^ gf_mul(a[1],3) ^ a[2] ^ a[3]
        out[4*c+1] = a[0] ^ gf_mul(a[1],2) ^ gf_mul(a[2],3) ^ a[3]
        out[4*c+2] = a[0] ^ a[1] ^ gf_mul(a[2],2) ^ gf_mul(a[3],3)
        out[4*c+3] = gf_mul(a[0],3) ^ a[1] ^ a[2] ^ gf_mul(a[3],2)
    return [x ^ mask for x in out]


def inv_mix_columns(state):
    out = [0] * 16
    for c in range(4):
        a = state[4*c:4*c+4]
        out[4*c+0] = gf_mul(a[0],14) ^ gf_mul(a[1],11) ^ gf_mul(a[2],13) ^ gf_mul(a[3],9)
        out[4*c+1] = gf_mul(a[0],9) ^ gf_mul(a[1],14) ^ gf_mul(a[2],11) ^ gf_mul(a[3],13)
        out[4*c+2] = gf_mul(a[0],13) ^ gf_mul(a[1],9) ^ gf_mul(a[2],14) ^ gf_mul(a[3],11)
        out[4*c+3] = gf_mul(a[0],11) ^ gf_mul(a[1],13) ^ gf_mul(a[2],9) ^ gf_mul(a[3],14)
    return out


def encrypt_custom(block, key, mask=0x54):
    rk = expand_key(key)
    s = xor_round_mask(add_key(list(block), rk[0]))
    for r in range(1, 10):
        s = [S[x] ^ 0xA1 for x in s]
        s = shift_rows(s)
        s = mix_columns(s, mask)
        s = xor_round_mask(add_key(s, rk[r]))
    s = [S[x] ^ 0xA1 for x in s]
    s = shift_rows(s)
    s = xor_round_mask(add_key(s, rk[10]))
    return bytes(s)


def decrypt_custom(block, key, mask=0x54):
    rk = expand_key(key)
    s = add_key(xor_round_mask(list(block)), rk[10])
    s = inv_shift_rows(s)
    s = [IS[x ^ 0xA1] for x in s]
    for r in range(9, 0, -1):
        s = add_key(xor_round_mask(s), rk[r])
        s = [x ^ mask for x in s]
        s = inv_mix_columns(s)
        s = inv_shift_rows(s)
        s = [IS[x ^ 0xA1] for x in s]
    s = add_key(xor_round_mask(s), rk[0])
    return bytes(s)


sample = bytes(range(16))
for label, key in KEYS.items():
    assert decrypt_custom(encrypt_custom(sample, key), key) == sample, 'custom AES roundtrip failed'
    plain = decrypt_custom(CIPHERTEXT, key)
    roundtrip = encrypt_custom(plain, key)
    print(f'{label}: key_hex={key.hex().upper()}')
    print(f'  plaintext_hex={plain.hex().upper()}')
    print(f'  plaintext_bytes={plain!r}')
    print(f'  custom_roundtrip={roundtrip.hex().upper()} matches_target={roundtrip == CIPHERTEXT}')
