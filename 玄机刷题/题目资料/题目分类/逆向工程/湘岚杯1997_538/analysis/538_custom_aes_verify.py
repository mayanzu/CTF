from pathlib import Path
import re
import struct

analysis = Path(__file__).resolve().parent
exe = analysis / '123.exe'
data = exe.read_bytes()
pe = struct.unpack_from('<I', data, 0x3c)[0]
sections_count = struct.unpack_from('<H', data, pe + 6)[0]
optional_size = struct.unpack_from('<H', data, pe + 20)[0]
section_table = pe + 24 + optional_size
section = None
for i in range(sections_count):
    o = section_table + 40 * i
    name = data[o:o+8].split(b'\0', 1)[0].decode('ascii')
    if name == '.data':
        section = (struct.unpack_from('<I', data, o + 12)[0], struct.unpack_from('<I', data, o + 20)[0])
        break
assert section is not None
# objdump symbol table locates RC, SBOX and INV_SBOX at .data+0x20/+0x40/+0x140.
data_rva, data_raw = section
rcon = data[data_raw+0x20:data_raw+0x2c]
sbox = data[data_raw+0x40:data_raw+0x140]
inv_sbox = data[data_raw+0x140:data_raw+0x240]
assert len(sbox) == len(inv_sbox) == 256
assert sbox[:4] == bytes.fromhex('637c777b') and inv_sbox[:4] == bytes.fromhex('52096ad5')
listing = (analysis / '538_objdump_main.txt').read_text(encoding='utf-8-sig', errors='replace')
stack = {}
for line in listing.splitlines():
    m = re.search(r'/[rbp\+0x([0-9a-fA-F]+)/],0x([0-9a-fA-F]+)', line)
    if m:
        stack[int(m.group(1), 16)] = int(m.group(2), 16)
ciphertext = bytes(stack[i] for i in range(0xA0, 0xC0))
key = bytes(stack[i] for i in range(0xC0, 0xD0))
assert len(ciphertext) == 32 and len(key) == 16

def expand_key(key):
    words = [list(key[i:i+4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = words[i-1][:]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [sbox[x] for x in temp]
            temp[0] ^= rcon[i//4-1]
        words.append([words[i-4][j] ^ temp[j] for j in range(4)])
    return [bytes(sum(words[4*r:4*r+4], [])) for r in range(11)]

def gf_mul(a, b):
    out = 0
    while b:
        if b & 1:
            out ^= a
        a = ((a << 1) ^ (0x11b if a & 0x80 else 0)) & 0xff
        b >>= 1
    return out

def shift_rows(state):
    s = state[:]
    # Exact byte moves from shift_rows disassembly at 0x401574.
    for inds in ([0, 4, 8, 12], [2, 6, 10, 14]):
        old = [s[i] for i in inds]
        new = old[-1:] + old[:-1]
        for i, x in zip(inds, new): s[i] = x
    s[1], s[9] = s[9], s[1]
    s[5], s[13] = s[13], s[5]
    return s

def inv_shift_rows(state):
    s = state[:]
    for inds in ([2, 6, 10, 14], [0, 4, 8, 12]):
        old = [s[i] for i in inds]
        new = old[1:] + old[:1]
        for i, x in zip(inds, new): s[i] = x
    s[1], s[9] = s[9], s[1]
    s[5], s[13] = s[13], s[5]
    return s

def mix_columns(state):
    out = state[:]
    for base in range(0, 16, 4):
        a = state[base:base+4]
        total = a[0] ^ a[1] ^ a[2] ^ a[3]
        for j in range(4):
            out[base+j] = a[j] ^ total ^ gf_mul(a[j] ^ a[(j+1)%4], 2)
    return out

def inv_mix_columns(state):
    out = state[:]
    for base in range(0, 16, 4):
        a = state[base:base+4]
        for j, coeffs in enumerate(((14,11,13,9),(9,14,11,13),(13,9,14,11),(11,13,9,14))):
            out[base+j] = gf_mul(a[0], coeffs[0]) ^ gf_mul(a[1], coeffs[1]) ^ gf_mul(a[2], coeffs[2]) ^ gf_mul(a[3], coeffs[3])
    return out

def encrypt_custom(block, keys):
    s = [a ^ b for a,b in zip(block, keys[0])]
    for rnd in range(1, 10):
        s = [inv_sbox[x] for x in s]
        s = shift_rows(s)
        s = mix_columns(s)
        s = [a ^ b for a,b in zip(s, keys[rnd])]
    s = [inv_sbox[x] for x in s]
    s = shift_rows(s)
    s = [a ^ b for a,b in zip(s, keys[10])]
    return bytes(s)

def decrypt_custom(block, keys):
    s = [a ^ b for a,b in zip(block, keys[10])]
    s = inv_shift_rows(s)
    s = [sbox[x] for x in s]
    for rnd in range(9, 0, -1):
        s = [a ^ b for a,b in zip(s, keys[rnd])]
        s = inv_mix_columns(s)
        s = inv_shift_rows(s)
        s = [sbox[x] for x in s]
    s = [a ^ b for a,b in zip(s, keys[0])]
    return bytes(s)

keys = expand_key(key)
blocks = [ciphertext[i:i+16] for i in (0,16)]
plain_blocks = [decrypt_custom(block, keys) for block in blocks]
plaintext = b''.join(plain_blocks)
roundtrip = b''.join(encrypt_custom(p, keys) for p in plain_blocks)
print(f'KEY_ASCII={key.decode("ascii")}')
print(f'KEY_HEX={key.hex()}')
print(f'RC_BYTES={rcon.hex()}')
print(f'CIPHERTEXT={ciphertext.hex()}')
print(f'PLAINTEXT_HEX={plaintext.hex()}')
print(f'PLAINTEXT_REPR={plaintext!r}')
print(f'PLAINTEXT_ASCII={plaintext.decode("ascii", errors="backslashreplace")}')
print(f'PLAINTEXT_LEN={len(plaintext)}')
whitespace_offsets = [i for i, value in enumerate(plaintext) if value in (9, 10, 11, 12, 13, 32)]
print(f'ASCII_WHITESPACE_OFFSETS={whitespace_offsets}')
print(f'FIRST_SCANF_TOKEN_LEN={whitespace_offsets[0] if whitespace_offsets else len(plaintext)}')
print(f'CUSTOM_REENCRYPT={roundtrip.hex()}')
print(f'ROUNDTRIP_MATCH={roundtrip == ciphertext}')
print(f'FLAG_SHAPE={plaintext.startswith(b"flag{") and plaintext.endswith(b"}")}')
