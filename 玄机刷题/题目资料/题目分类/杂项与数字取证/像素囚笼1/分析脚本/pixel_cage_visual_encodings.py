from itertools import product, permutations
from pathlib import Path
from zipfile import ZipFile

IMAGE = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
seq = ["blue", "red", "yellow", "green", "purple", "cyan", "blue", "red"]
hex_by_color = {
    "blue": "4285F4", "red": "DB4437", "yellow": "F4B400",
    "green": "0F9D58", "purple": "AB47BC", "cyan": "00ACC1",
}
rgb_by_color = {
    "blue": (66, 133, 244), "red": (219, 68, 55), "yellow": (244, 180, 0),
    "green": (15, 157, 88), "purple": (171, 71, 188), "cyan": (0, 172, 193),
}
alts = {"purple": ("violet", "magenta"), "cyan": ("aqua", "turquoise"),
        "blue": ("azure",), "red": ("crimson",), "yellow": ("gold",),
        "green": ("lime",)}
candidates = set()
seps = ("", " ", "-", "_")

# Exact left-to-right circle color sequence, with every per-item case pattern.
for mask in range(1 << len(seq)):
    words = [w.upper() if mask & (1 << i) else w for i, w in enumerate(seq)]
    initials = [w[0] for w in words]
    for sep in seps:
        candidates.add(sep.join(words))
        candidates.add(sep.join(initials))

# Unique square-color orders, allowing common palette-name variants.
unique = ["blue", "red", "yellow", "green", "purple", "cyan"]
for order in permutations(unique):
    for sep in ("", "-", "_"):
        candidates.add(sep.join(order))
        candidates.add(sep.join(w.upper() for w in order))
        candidates.add(sep.join(w.title() for w in order))

for choices in product(*(alts[c] + (c,) for c in unique)):
    name_for = dict(zip(unique, choices))
    for sep in ("", "-", "_"):
        candidates.add(sep.join(name_for[c] for c in seq))
        candidates.add(sep.join(name_for[c].title() for c in seq))

# Palette values in visual order, represented as hex or decimal RGB triples.
hexes = [hex_by_color[c] for c in seq]
rgbs = [rgb_by_color[c] for c in seq]
for sep in ("", " ", ",", "-", "_"):
    candidates.add(sep.join(hexes))
    candidates.add(sep.join(h.lower() for h in hexes))
    candidates.add(sep.join("#" + h for h in hexes))
    candidates.add(sep.join(str(n) for rgb in rgbs for n in rgb))
    candidates.add(sep.join(".".join(map(str, rgb)) for rgb in rgbs))
    candidates.add(sep.join(f"{r:02X}{g:02X}{b:02X}" for r, g, b in rgbs))

# Circle size/center coordinate sequences and size-color pairs.
diameters = [40, 46, 52, 58, 64, 70, 76, 82]
centers = [80, 135, 190, 245, 300, 355, 410, 465]
grid_xy = [(90, 110), (165, 250), (240, 390), (315, 110),
           (390, 250), (465, 390), (90, 110), (165, 250)]
for values in (diameters, centers, [v // 2 for v in diameters]):
    for sep in ("", " ", ",", "-", "_"):
        candidates.add(sep.join(map(str, values)))
for sep in ("", " ", ",", "-", "_"):
    candidates.add(sep.join(f"{x}{y}" for x, y in grid_xy))
    candidates.add(sep.join(f"{x},{y}" for x, y in grid_xy))
    candidates.add(sep.join(f"{x}:{y}" for x, y in grid_xy))

with ZipFile(IMAGE) as archive:
    for i, password in enumerate(sorted(candidates), 1):
        try:
            data = archive.read("secret.txt", pwd=password.encode("utf-8"))
        except Exception:
            continue
        print(f"PASSWORD FOUND: {password!r}")
        print(f"SECRET.TXT: {data.decode(errors='replace')!r}")
        break
    else:
        print(f"No match across {len(candidates)} case/name/color-value/geometry candidates.")
