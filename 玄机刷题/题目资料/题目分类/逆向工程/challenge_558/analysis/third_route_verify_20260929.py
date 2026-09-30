from __future__ import annotations

RAW_KEY = bytes.fromhex('6c 6e 74 66 76 70 75 73')
TARGET = bytes.fromhex('18 59 07 28 f4 ad c8 c3 b6 3f 2d 39 ca 34 d1 8e f5 03 b0')
EXPECTED = b'flag{8a1c2a73c29b2}'

def effective_key(raw: bytes) -> bytes:
    return bytes(value ^ index for index, value in enumerate(raw))

def ksa(key: bytes) -> list[int]:
    state = list(range(256))
    j = 0
    for i in range(256):
        key_byte = key[i % len(key)] ^ 0x66
        j = (j + state[i] + key_byte) & 0xff
        state[i], state[j] = state[j], state[i]
    return state

def nibble_swap(value: int) -> int:
    return ((value << 4) | (value >> 4)) & 0xff

def next_mask(state: list[int], ij: list[int]) -> int:
    i, j = ij
    i = (i + 1) & 0xff
    j = (j + state[i]) & 0xff
    state[i], state[j] = state[j], state[i]
    k = state[(state[i] + state[j]) & 0xff]
    ij[:] = [i, j]
    return (nibble_swap(k) + 1) & 0xff

key = effective_key(RAW_KEY)
print('raw_key_ascii=', RAW_KEY.decode('ascii'))
print('key_xor_index_rows=')
for i, value in enumerate(RAW_KEY):
    print(f'  i={i} raw=0x{value:02x} xor=0x{i:02x} effective=0x{value ^ i:02x} char={chr(value ^ i)}')
print('effective_key_ascii=', key.decode('ascii'))
print('target_len=', len(TARGET), 'target_hex=', TARGET.hex())

state = ksa(key)
print('ksa_state_len=', len(state), 'ksa_state_prefix16=', bytes(state[:16]).hex())
indices = [0, 0]
plaintext = bytearray()
rows = []
for index, cipher_byte in enumerate(TARGET):
    mask = next_mask(state, indices)
    plain_byte = ((cipher_byte - 1) & 0xff) ^ mask
    plaintext.append(plain_byte)
    rows.append((index, plain_byte, mask, cipher_byte))
print('candidate_bytes=', bytes(plaintext).hex())
print('candidate_ascii=', bytes(plaintext).decode('ascii'))
print('candidate_matches_expected=', bytes(plaintext) == EXPECTED)
print('per_byte_forward_check: idx plain mask cipher_recalc cipher_target ok')

state = ksa(key)
indices = [0, 0]
recalculated = bytearray()
all_ok = True
for index, plain_byte, decrypt_mask, target_byte in rows:
    forward_mask = next_mask(state, indices)
    cipher_byte = ((plain_byte ^ forward_mask) + 1) & 0xff
    recalculated.append(cipher_byte)
    ok = forward_mask == decrypt_mask and cipher_byte == target_byte
    all_ok = all_ok and ok
    print(f'{index:02d}   {plain_byte:02x}    {forward_mask:02x}   {cipher_byte:02x}          {target_byte:02x}         {ok}')
print('forward_hex=', recalculated.hex())
print('forward_matches_target=', bytes(recalculated) == TARGET)
print('all_19_byte_masks_and_ciphertext_match=', all_ok)
assert key == b'loverust'
assert bytes(plaintext) == EXPECTED
assert bytes(recalculated) == TARGET
assert all_ok