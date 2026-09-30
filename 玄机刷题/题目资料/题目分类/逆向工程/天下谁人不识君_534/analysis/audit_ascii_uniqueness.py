alphabet = 'wesyvbniazxchjko1973652048@$+-&*<>'
ciphertext = 'v7b3boika$h4h5j0jhkh161h79393i5x010j0y8n$i'
assert len(alphabet) == 34 and len(set(alphabet)) == 34
assert len(ciphertext) % 2 == 0

def encode_char(ch, i):
    code = ord(ch)
    return alphabet[(code // 17 + i) % 34] + alphabet[-(code % 17 + i + 1) % 34]

recovered = []
for i in range(len(ciphertext) // 2):
    pair = ciphertext[2*i:2*i+2]
    matches = [chr(code) for code in range(32, 127) if encode_char(chr(code), i) == pair]
    assert len(matches) == 1, (i, pair, matches)
    recovered.append(matches[0])
    print(f'i={i:02d}, pair={pair!r}, printable-ASCII matches={matches[0]!r} (exactly one)')
flag = ''.join(recovered)
print('unique printable-ASCII plaintext:', flag)
assert flag == 'SQCTF{libai_jianxian}'