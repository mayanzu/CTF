from pathlib import Path
c = (Path(__file__).resolve().parent / '1.enc').read_bytes()
variants = []
def add(name, data):
    if b'flag{' in data.lower() or b'sqctf{' in data.lower():
        variants.append((name, data))

for rev in (False, True):
    x = c[::-1] if rev else c
    for k in range(256):
        add(f'xor-const-{k:02x}-rev{rev}', bytes(v ^ k for v in x))
        add(f'add-const-{k:02x}-rev{rev}', bytes((v + k) & 255 for v in x))
        add(f'sub-const-{k:02x}-rev{rev}', bytes((v - k) & 255 for v in x))
    for a in range(256):
        for b in range(256):
            add(f'xor-linear-a{a}-b{b}-rev{rev}', bytes(v ^ ((a*i+b)&255) for i,v in enumerate(x)))
            add(f'add-linear-a{a}-b{b}-rev{rev}', bytes((v + a*i+b)&255 for i,v in enumerate(x)))
            add(f'sub-linear-a{a}-b{b}-rev{rev}', bytes((v - a*i-b)&255 for i,v in enumerate(x)))
    for key in (b'2493', b'flag', b'life', b'anya', b'jerry', b'tom'):
        for op in ('xor','add','sub'):
            out=[]
            for i,v in enumerate(x):
                k=key[i%len(key)]
                out.append((v^k) if op=='xor' else ((v+k)&255 if op=='add' else (v-k)&255))
            add(f'{op}-repeat-{key!r}-rev{rev}', bytes(out))
print('matches for direct/linear byte transforms:', len(variants))
for name, data in variants[:100]: print(name, data.hex(), repr(data))
