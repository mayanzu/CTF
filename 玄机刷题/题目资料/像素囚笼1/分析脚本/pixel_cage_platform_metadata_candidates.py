from itertools import product
from pathlib import Path
from zipfile import ZipFile

IMAGE = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
parts = ["2026", "09", "21", "20", "46", "41", "583", "570", "20260921",
         "20260921204641", "2026安网杯", "安网杯", "玄机", "edisec", "xj",
         "flag", "testflag", "测试flag", "Abstract", "Gallery", "BRYGPCBR"]
candidates = set(parts)
for n in (2, 3, 4):
    for values in product(parts[:7], repeat=n):
        s = "".join(values)
        candidates.add(s)
        candidates.add(s.lower())
        candidates.add("_".join(values))
        candidates.add("-".join(values))
for date in ("20260921", "2026-09-21", "2026.09.21", "2026/09/21",
             "21092026", "09212026", "20260921204641", "2026-09-21-204641"):
    for tail in ("", "583", "570", "xj", "edisec", "flag", "2026", "BRYGPCBR"):
        for sep in ("", "-", "_", "."):
            candidates.add(date + sep + tail)
            candidates.add(tail + sep + date)

with ZipFile(IMAGE) as archive:
    for password in sorted(candidates):
        try:
            data = archive.read("secret.txt", pwd=password.encode("utf-8"))
        except Exception:
            continue
        print(f"PASSWORD FOUND: {password!r}")
        print(f"SECRET.TXT: {data.decode(errors='replace')!r}")
        break
    else:
        print(f"No match across {len(candidates)} platform date/time/ID candidates.")
