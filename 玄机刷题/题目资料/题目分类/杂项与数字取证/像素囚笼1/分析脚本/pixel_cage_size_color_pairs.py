from itertools import permutations
from pathlib import Path
from zipfile import ZipFile

IMAGE = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
SEQ = "BRYGPCBR"
COLORS = sorted(set(SEQ))
DIAMETERS = [40, 46, 52, 58, 64, 70, 76, 82]
SIZE_RANKS = list(range(1, 9))
ROWS = [1, 2, 3, 1, 2, 3, 1, 2]
COLS = [1, 1, 1, 2, 2, 2, 1, 1]
candidates = set()

def letters(values, offset=0):
    return "".join(chr(97 + (v + offset) % 26) for v in values)

for order in permutations(COLORS):
    color_id = {c: i for i, c in enumerate(order)}
    colors = [color_id[c] for c in SEQ]
    for sizes in (SIZE_RANKS, DIAMETERS, [d // 2 for d in DIAMETERS]):
        for a, b in ((colors, sizes), (sizes, colors)):
            for mode in ("concat", "sum", "difference", "product"):
                if mode == "concat":
                    candidates.add("".join(f"{x}{y}" for x, y in zip(a, b)))
                    candidates.add("".join(f"{y}{x}" for x, y in zip(a, b)))
                    continue
                if mode == "sum": values = [x + y for x, y in zip(a, b)]
                elif mode == "difference": values = [x - y for x, y in zip(a, b)]
                else: values = [x * y for x, y in zip(a, b)]
                for offset in range(26):
                    candidates.add(letters(values, offset))
                    candidates.add(letters(values[::-1], offset))
                    candidates.add("".join(str((v + offset) % 10) for v in values))

# Also combine each circle's size rank with its matching square's grid position.
for sizes in (SIZE_RANKS, DIAMETERS, [d // 2 for d in DIAMETERS]):
    for coord in (ROWS, COLS):
        for a, b in ((sizes, coord), (coord, sizes)):
            candidates.add("".join(f"{x}{y}" for x, y in zip(a, b)))
            candidates.add("".join(f"{x},{y}" for x, y in zip(a, b)))
            values = [x + b0 for x, b0 in zip(a, b)]
            for offset in range(26):
                candidates.add(letters(values, offset))
                candidates.add("".join(str((v + offset) % 10) for v in values))

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
        print(f"No match across {len(candidates)} combined size/color/grid candidates.")
