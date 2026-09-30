from collections import Counter
from itertools import permutations
from pathlib import Path
from zipfile import ZipFile
from PIL import Image
import hashlib

IMAGE = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
seq = "BRYGPCBR"
rgb = {"B": (66,133,244), "R": (219,68,55), "Y": (244,180,0),
       "G": (15,157,88), "P": (171,71,188), "C": (0,172,193)}
counts = Counter(Image.open(IMAGE).convert("RGB").getdata())
area = {c: counts[color] for c,color in rgb.items()}
base = [area[c] for c in seq]
unique = [area[c] for c in "BRYGPC"]
print("visible fill pixel counts in circle order:", base)
candidates = set()

def add_values(vals):
    vals = list(vals)
    if len(vals) != 8:
        vals = vals + [0] * (8-len(vals)) if len(vals)<8 else vals[:8]
    for sep in ("", ",", "-", "_", ".", " "):
        candidates.add(sep.join(map(str, vals)))
        candidates.add(sep.join(f"{v:02d}" for v in vals))
    for mod in (10, 26, 36, 100):
        for offset in range(mod):
            mapped = [(v + offset) % mod for v in vals]
            candidates.add("".join(map(str, mapped)))
            if mod == 26:
                candidates.add("".join(chr(97+v) for v in mapped))
                candidates.add("".join(chr(65+v) for v in mapped))
    for sep in ("", ",", "-", "_"):
        raw = sep.join(map(str, vals))
        candidates.add(hashlib.md5(raw.encode()).hexdigest())
        candidates.add(hashlib.sha1(raw.encode()).hexdigest())

for vals in (base, [v-9409 for v in base], [v-10000 for v in base],
             [v//10 for v in base], [v//100 for v in base], [v//1000 for v in base],
             [v%26 for v in base], [v%100 for v in base],
             sorted(base), sorted(base, reverse=True),
             [base[i]-base[i-1] for i in range(1,len(base))]):
    add_values(vals)
for order in permutations("BRYGPC"):
    vals = [area[c] for c in order]
    add_values(vals)
    add_values([v-9409 for v in vals])
    add_values([v%26 for v in vals])

with ZipFile(IMAGE) as archive:
    for password in sorted(candidates):
        try:
            data = archive.read("secret.txt", pwd=password.encode("ascii"))
        except Exception:
            continue
        print(f"PASSWORD FOUND: {password!r}")
        print(f"SECRET.TXT: {data.decode(errors='replace')!r}")
        break
    else:
        print(f"No match across {len(candidates)} pixel-count candidates.")
