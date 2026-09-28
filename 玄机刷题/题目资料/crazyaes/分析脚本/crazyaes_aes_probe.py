from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

cipher = bytes.fromhex('B43836301E6848575101B7039B98E37E')
key = bytearray(b'gah43jJKgfjGMeAR')

def transforms(b):
    m = [list(b[i:i+4]) for i in range(0, 16, 4)]
    t = bytes(m[r][c] for c in range(4) for r in range(4))
    return {'id': bytes(b), 'rev': bytes(b[::-1]), 'transpose': t,
            'wordrev': b''.join(bytes(b[i:i+4][::-1]) for i in range(0,16,4)),
            'wordsrev': b''.join(b[i:i+4] for i in range(12,-1,-4)),
            'rot1': bytes(b[1:]+b[:1]), 'rowsrev': bytes(sum(m[::-1], [])),
            'colsrev': bytes(sum([row[::-1] for row in m], []))}

def aes(data, k, decrypt):
    c = Cipher(algorithms.AES(k), modes.ECB())
    x = c.decryptor() if decrypt else c.encryptor()
    return x.update(data) + x.finalize()

hits = []
for kn, kv in [('runtime', bytes(key)), ('preinit', b'ga!43jJKgfjGMeAR')]:
    for kt, k in transforms(kv).items():
        for ct, c in transforms(cipher).items():
            for decrypt in (True, False):
                p = aes(c, k, decrypt)
                score = sum(32 <= x < 127 for x in p)
                if score >= 13 or p.startswith(b'flag') or b'flag{' in p:
                    hits.append((score, kn, kt, ct, 'dec' if decrypt else 'enc', p))
for row in sorted(hits, reverse=True):
    print(row)
print('hit_count=', len(hits))
