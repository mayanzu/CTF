from hashlib import sha256

alphabet = 'wesyvbniazxchjko1973652048@$+-&*<>'
ciphertext = 'v7b3boika$h4h5j0jhkh161h79393i5x010j0y8n$i'
size = len(alphabet)
assert size == 34 and len(set(alphabet)) == size
assert len(ciphertext) % 2 == 0
index = {ch: pos for pos, ch in enumerate(alphabet)}

print(f'alphabet length={size}; unique={len(index)}')
print(f'ciphertext length={len(ciphertext)}; decoded character count={len(ciphertext)//2}')
recovered = []
for i in range(len(ciphertext) // 2):
    first, second = ciphertext[2*i:2*i+2]
    j1, j2 = index[first], index[second]
    q = (j1 - i) % size
    r = (-j2 - i - 1) % size
    codepoint = 17*q + r
    assert 0 <= q <= 7, (i, first, second, q, r)
    assert 0 <= r <= 16, (i, first, second, q, r)
    recovered.append(chr(codepoint))
    print(f'i={i:02d} pair={first!r}{second!r} indices=({j1:02d},{j2:02d}) q={q} r={r:02d} codepoint={codepoint:03d} char={chr(codepoint)!r}')
flag = ''.join(recovered)
print('recovered flag:', flag)

reencoded = ''.join(
    alphabet[(ord(ch)//17 + i) % size] + alphabet[-(ord(ch)%17 + i + 1) % size]
    for i, ch in enumerate(flag)
)
print('re-encoded ciphertext:', reencoded)
print('matches source comment:', reencoded == ciphertext)
assert reencoded == ciphertext