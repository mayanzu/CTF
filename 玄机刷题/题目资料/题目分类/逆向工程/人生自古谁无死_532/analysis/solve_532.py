from pathlib import Path
import struct

MASK = 0xffffffff

def rol32(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK

def qr(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & MASK; x[d] ^= x[a]; x[d] = rol32(x[d], 16)
    x[c] = (x[c] + x[d]) & MASK; x[b] ^= x[c]; x[b] = rol32(x[b], 12)
    x[a] = (x[a] + x[b]) & MASK; x[d] ^= x[a]; x[d] = rol32(x[d], 8)
    x[c] = (x[c] + x[d]) & MASK; x[b] ^= x[c]; x[b] = rol32(x[b], 7)

def chacha_block(state):
    work = state.copy()
    for _ in range(10):
        qr(work, 0, 4, 8, 12); qr(work, 1, 5, 9, 13)
        qr(work, 2, 6, 10, 14); qr(work, 3, 7, 11, 15)
        qr(work, 0, 5, 10, 15); qr(work, 1, 6, 11, 12)
        qr(work, 2, 7, 8, 13); qr(work, 3, 4, 9, 14)
    return struct.pack('<16I', *[((work[i] + state[i]) & MASK) for i in range(16)])

def show_bytes(label, data):
    print(f'{label} ({len(data)} bytes):')
    print('  hex =', data.hex())
    print('  ascii=', repr(data.decode('ascii', errors='backslashreplace')))

script_dir = Path(__file__).resolve().parent
asset_dir = script_dir if (script_dir / '1.enc').exists() else script_dir.parent / 'extracted'
enc1 = (asset_dir / '1.enc').read_bytes()
enc2 = (asset_dir / '2.enc').read_bytes()
show_bytes('1.enc', enc1)
show_bytes('2.enc', enc2)

# 1.enc's standalone reversible transform: reverse the entire file, then XOR every byte by 0x55.
flag1 = bytes(b ^ 0x55 for b in enc1[::-1])
show_bytes('1.enc reversed then XOR 0x55', flag1)
assert flag1.startswith(b'flag{') and flag1.endswith(b'}')

# Rebuild the exact 64-byte ChaCha state from the program's static data and instruction sequence.
sigma = b'expand 32-byte k'
obf2 = bytes.fromhex('deadbeef')  # memory order: DE AD BE EF
key = bytes(((i + 0x11) & 0xff) ^ obf2[i % 4] for i in range(32))
nonce = bytes((i * 0x11) & 0xff for i in range(12))
counter = bytes(4)
state_bytes = sigma + key + counter + nonce
assert len(sigma) == 16 and len(key) == 32 and len(state_bytes) == 64
state = list(struct.unpack('<16I', state_bytes))
stream = chacha_block(state)
print('ChaCha state words =', ' '.join(f'{w:08x}' for w in state))
print('ChaCha key         =', key.hex())
print('ChaCha counter     =', counter.hex())
print('ChaCha nonce       =', nonce.hex())
print('ChaCha keystream   =', stream.hex())

# The ciphertext byte sequence is target_str at PE .rdata RVA 0x5070 (25 bytes before NUL).
target_ct = bytes.fromhex('d0a114b758fa859141531b6038aba50229cbdd284e67e632d9')
target_plain = bytes(a ^ b for a, b in zip(target_ct, stream))
show_bytes('target_str XOR ChaCha20(first 25 bytes)', target_plain)

# 2.enc XOR the same stream exposes the same flag prefix as 1.enc, but only the first 16 hex digits.
flag2_part = bytes(a ^ b for a, b in zip(enc2, stream))
show_bytes('2.enc XOR ChaCha20 keystream', flag2_part)
normalized = flag2_part.decode('ascii').replace('-', '').removesuffix('}')
full = flag1.decode('ascii').removesuffix('}')
print('2.enc normalized prefix =', normalized)
print('1.enc full candidate    =', flag1.decode('ascii'))
print('2.enc prefix matches 1.enc =', full.startswith(normalized))
assert full.startswith(normalized)

# The program's decoy routine receives n=29: XOR only bytes 0..28 and reverse only that prefix.
decoy = bytes.fromhex('28213c383720260a213a3b0a3a310a323439330a303e34332e1301160406')
decoy_result = bytes(b ^ 0x55 for b in decoy[:29])[::-1] + decoy[29:]
show_bytes('actual decoy_str after XOR/reverse n=29', decoy_result)

