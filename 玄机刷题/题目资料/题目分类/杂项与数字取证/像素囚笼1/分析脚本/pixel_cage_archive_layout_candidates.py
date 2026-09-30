from itertools import product
from pathlib import Path
from zipfile import ZipFile

IMAGE = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
values = [4956, 4996, 5109, 5165, 5187, 113, 125, 239, 0x9D13B619,
          512, 10, 583, 20260921]
candidates = set()
for n in values:
    candidates.update({str(n), str(n).zfill(4), str(n).zfill(6), hex(n)[2:], hex(n)[2:].upper()})
    for s in (str(n), str(n).zfill(4), hex(n)[2:], hex(n)[2:].upper()):
        candidates.add(s[::-1])
        candidates.add("0x" + s)
        candidates.add("#" + s)
for a, b in product(values, repeat=2):
    aa, bb = str(a), str(b)
    for sep in ("", "-", "_", ".", ","):
        candidates.add(aa + sep + bb)
        candidates.add(bb + sep + aa)
for s in ("4956", "4996", "5109", "5165", "5187", "113", "125", "239", "9d13b619"):
    for tail in ("", "flag", "secret", "zip", "png", "583", "2026"):
        candidates.add(s + tail)
        candidates.add(tail + s)

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
        print(f"No match across {len(candidates)} archive-layout/metadata candidates.")
