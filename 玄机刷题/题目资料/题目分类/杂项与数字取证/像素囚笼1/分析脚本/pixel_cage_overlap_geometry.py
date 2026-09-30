from pathlib import Path
from zipfile import ZipFile
import hashlib

IMAGE = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
seq = "BRYGPCBR"
square = {"B": (90, 110), "R": (165, 250), "Y": (240, 390),
          "G": (315, 110), "P": (390, 250), "C": (465, 390)}
circle_x = [80, 135, 190, 245, 300, 355, 410, 465]
circle_y = [420] * 8
diameters = [40, 46, 52, 58, 64, 70, 76, 82]
radii = [d // 2 for d in diameters]
sx = [square[c][0] for c in seq]
sy = [square[c][1] for c in seq]
dx = [b - a for a, b in zip(circle_x, sx)]
dy = [b - a for a, b in zip(sy, circle_y)]
features = {
    "dx": dx, "dy": dy,
    "dx_abs": [abs(x) for x in dx], "dy_abs": [abs(y) for y in dy],
    "manhattan": [abs(x) + abs(y) for x, y in zip(dx, dy)],
    "signed_sum": [x + y for x, y in zip(dx, dy)],
    "signed_diff": [x - y for x, y in zip(dx, dy)],
    "circle_x": circle_x, "square_x": sx, "square_y": sy,
    "radius": radii, "diameter": diameters,
    "circle_diameter_vs_center_gap": [55 - d for d in diameters[:-1]] + [465 + 41 - 512],
    "adjacent_overlap": [radii[i] + radii[i + 1] - 55 for i in range(7)],
}
candidates = set()
for label, values in features.items():
    if len(values) != 8:
        # Extend seven adjacent-pair metrics with common neutral/edge values.
        values = values + [0]
    for sep in ("", ",", "-", "_", ".", " "):
        candidates.add(sep.join(map(str, values)))
        candidates.add(sep.join(f"{v:02d}" for v in values))
    for divisor in (2, 5, 10, 20, 25, 50, 55, 75, 100, 140):
        if all(v % divisor == 0 for v in values):
            reduced = [v // divisor for v in values]
            candidates.add("".join(map(str, reduced)))
            candidates.add(",".join(map(str, reduced)))
    for modulus in (10, 26):
        for offset in range(modulus):
            mapped = [(v + offset) % modulus for v in values]
            candidates.add("".join(map(str, mapped)))
            if modulus == 26:
                candidates.add("".join(chr(97 + v) for v in mapped))
                candidates.add("".join(chr(65 + v) for v in mapped))
    for sep in ("", ",", "-", "_"):
        raw = sep.join(map(str, values))
        candidates.add(hashlib.md5(raw.encode()).hexdigest())
        candidates.add(hashlib.sha1(raw.encode()).hexdigest())

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
        print(f"No match across {len(candidates)} square-circle offset/overlap candidates.")
