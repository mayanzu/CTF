from itertools import product
from pathlib import Path
from zipfile import ZipFile

IMAGE = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
seq = ["blue", "red", "yellow", "green", "purple", "cyan", "blue", "red"]
diameters = [40, 46, 52, 58, 64, 70, 76, 82]
radii = [20, 23, 26, 29, 32, 35, 38, 41]
centers = [80, 135, 190, 245, 300, 355, 410, 465]
ranks = list(range(1, 9))
candidates = set()

for values in (diameters, radii, centers, ranks):
    for mask in range(1 << 8):
        names = [w.upper() if mask & (1 << i) else w for i, w in enumerate(seq)]
        initial = [w[0] for w in names]
        for sep in ("", ":", "-", "_", "=", ",", "."):
            for words in (names, initial):
                for order in (0, 1):
                    parts = [f"{w}{v}" if order == 0 else f"{v}{w}" for w, v in zip(words, values)]
                    candidates.add(sep.join(parts))
                    candidates.add(" ".join(f"{w}{sep}{v}" if order == 0 else f"{v}{sep}{w}" for w, v in zip(words, values)))
                    candidates.add("".join(f"({w}{sep}{v})" if order == 0 else f"({v}{sep}{w})" for w, v in zip(words, values)))

# Add positions and color names as compact pairs.
for values in (diameters, radii, centers, ranks):
    for sep in ("", ":", "-", "_", ",", ";"):
        candidates.add(sep.join(f"{w}{v}" for w, v in zip(seq, values)))
        candidates.add(sep.join(f"{v}{w}" for w, v in zip(seq, values)))

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
        print(f"No match across {len(candidates)} named-color/size/position candidates.")
