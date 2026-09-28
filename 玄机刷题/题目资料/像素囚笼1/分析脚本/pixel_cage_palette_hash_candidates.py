from itertools import permutations
from pathlib import Path
from zipfile import ZipFile
import base64, hashlib

IMAGE = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
names = ["blue", "red", "yellow", "green", "purple", "cyan"]
codes = {"blue":"4285F4", "red":"DB4437", "yellow":"F4B400", "green":"0F9D58", "purple":"AB47BC", "cyan":"00ACC1"}
seq = ["blue", "red", "yellow", "green", "purple", "cyan", "blue", "red"]
materials = set()
for order in (seq, ["blue","green","red","purple","yellow","cyan"], names):
    for sep in ("", ":", ",", "-", "_", " ", "#"):
        material = sep.join(codes[c] for c in order)
        materials.add(material)
        materials.add(material.lower())
        materials.add(sep.join("#"+codes[c] for c in order))
        materials.add(sep.join(codes[c] for c in order).lower())
for order in permutations(names):
    materials.add("".join(codes[c] for c in order))
    materials.add("".join(codes[c].lower() for c in order))
    materials.add("".join(c for c in order))

candidates=set()
for material in materials:
    raw=material.encode()
    variants=[raw,raw[::-1],raw.hex().encode(),base64.b64encode(raw),base64.urlsafe_b64encode(raw)]
    for b in variants:
        for h in (hashlib.md5,hashlib.sha1,hashlib.sha256,hashlib.sha512):
            d=h(b).digest(); x=h(b).hexdigest()
            candidates.add(x); candidates.add(x.upper())
            candidates.add(base64.b64encode(d).decode())
            candidates.add(base64.urlsafe_b64encode(d).decode())

with ZipFile(IMAGE) as archive:
    for password in sorted(candidates):
        try:
            data=archive.read("secret.txt",pwd=password.encode("ascii"))
        except Exception:
            continue
        print(f"PASSWORD FOUND: {password!r}")
        print(f"SECRET.TXT: {data.decode(errors='replace')!r}")
        break
    else:
        print(f"No match across {len(candidates)} palette hash/encoding candidates.")
