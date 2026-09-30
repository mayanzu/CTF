from itertools import permutations
from pathlib import Path
from zipfile import ZipFile
import base64, hashlib, colorsys

image = Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'
# Values read from the actual PNG pixels, not a remembered/older Google palette.
palette = {
    'blue': (66,133,244), 'red': (219,68,55), 'yellow': (244,180,0),
    'green': (15,157,88), 'purple': (171,71,188), 'cyan': (0,172,193),
}
seq = ['blue','red','yellow','green','purple','cyan','blue','red']
orders = [seq, ['blue','green','red','purple','yellow','cyan']]
orders.extend(permutations(palette))
materials = set()
for order in orders:
    hexes = [''.join(f'{x:02X}' for x in palette[c]) for c in order]
    rgbs = [palette[c] for c in order]
    for sep in ('','-', '_', ':', ',', '.', ' ', '#'):
        for form in (hexes, [x.lower() for x in hexes]):
            joined = sep.join(form)
            materials.update((joined, joined.upper(), joined.lower()))
            materials.add('#'.join(form))
        for vals in (rgbs, list(reversed(rgbs))):
            flat = [str(x) for rgb in vals for x in rgb]
            dotted = ['.'.join(map(str, rgb)) for rgb in vals]
            materials.add(sep.join(flat))
            materials.add(sep.join(dotted))
    raw = bytes(x for rgb in rgbs for x in rgb)
    for b in (raw, raw[::-1], bytes.fromhex(''.join(hexes)), bytes.fromhex(''.join(hexes))[::-1]):
        for item in (b, b.hex().encode(), base64.b64encode(b), base64.urlsafe_b64encode(b), base64.b32encode(b)):
            materials.add(item.decode('latin1') if isinstance(item, bytes) else item)
# Actual RGB/HSV channels per circle, plus straightforward text and numeric encodings.
rgbs = [palette[c] for c in seq]
for ch in range(3):
    vals = [rgb[ch] for rgb in rgbs]
    for sep in ('','-', '_', ':', ',', '.', ' '):
        for a in (vals, vals[::-1]):
            materials.add(sep.join(map(str,a)))
            materials.add(sep.join(f'{v:02d}' for v in a))
            materials.add(sep.join(f'{v:03d}' for v in a))
    for offset in range(256):
        materials.add(''.join(chr(65+((v+offset)%26)) for v in vals))
        materials.add(''.join(chr(97+((v+offset)%26)) for v in vals))
for c in palette:
    h,s,v = colorsys.rgb_to_hsv(*(q/255 for q in palette[c]))
    palette[c] = palette[c]
# Use original sequences to build exact per-circle HSV summaries.
for attr in range(3):
    vals=[]
    for c in seq:
        hsv=colorsys.rgb_to_hsv(*(q/255 for q in palette[c]))
        vals.append(hsv[attr])
    for scale in (1,10,100,1000,10000):
        nums=[round(v*scale) for v in vals]
        materials.add(''.join(map(str,nums)))
        materials.add('_'.join(map(str,nums)))
        materials.add('-'.join(map(str,nums)))
# Digest every direct representation using common hash/encoding choices.
candidates=set()
for m in materials:
    raw=m.encode('latin1', errors='ignore')
    candidates.add(m); candidates.add(m.lower()); candidates.add(m.upper())
    for b in (raw, raw[::-1]):
        for h in (hashlib.md5, hashlib.sha1, hashlib.sha256, hashlib.sha512):
            d=h(b).digest()
            candidates.add(d.hex()); candidates.add(d.hex().upper())
            candidates.add(base64.b64encode(d).decode())
            candidates.add(base64.urlsafe_b64encode(d).decode())
print('exact-color material variants:', len(materials))
print('password candidates including digest encodings:', len(candidates))
hits=[]
with ZipFile(image) as z:
    for i,pwd in enumerate(candidates,1):
        try:
            out=z.read('secret.txt',pwd=pwd.encode('latin1'))
        except Exception:
            continue
        hits.append((pwd,out)); break
print('full ZIP decrypt + CRC hits:',len(hits))
for pwd,out in hits: print('PASSWORD:',repr(pwd),'SECRET:',repr(out))

