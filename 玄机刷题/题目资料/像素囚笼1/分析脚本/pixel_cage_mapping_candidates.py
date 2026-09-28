from itertools import permutations
from pathlib import Path
from zipfile import ZipFile

IMAGE = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
SEQ = "BRYGPCBR"
SIZES = [40, 46, 52, 58, 64, 70, 76, 82]
colors = sorted(set(SEQ))
candidates = set()

# Treat every possible numbering of the six colored squares as a candidate key.
for order in permutations(colors):
    index = {color: i + 1 for i, color in enumerate(order)}
    digits = "".join(str(index[c]) for c in SEQ)
    letters = "".join(chr(64 + index[c]) for c in SEQ)
    for s in (digits, letters, letters.lower()):
        candidates.add(s)

# Common grid read orders: digits as A1Z26, coordinate pairs, and ranks paired
# with the growing circle sizes.
for order in ("BRYGPC", "BGRPYC", "RYGBPC", "RGBYPC", "BYRGPC", "BPRGYC"):
    index = {color: i + 1 for i, color in enumerate(order)}
    digit_seq = "".join(str(index[c]) for c in SEQ)
    candidates |= {digit_seq, "".join(chr(64 + int(ch)) for ch in digit_seq),
                   "".join(chr(96 + int(ch)) for ch in digit_seq)}

color_idx = {c: i + 1 for i, c in enumerate("BRYGPC")}
color_nums = [color_idx[c] for c in SEQ]
for vals in (SIZES, [s // 2 for s in SIZES], list(range(1, 9))):
    for left, right in ((vals, color_nums), (color_nums, vals)):
        candidates.add("".join(f"{a}{b}" for a, b in zip(left, right)))
        candidates.add("".join(chr(96 + ((a - 1) % 26) + 1) for a in left))

for word in ("google", "googlecolors", "googlecolor", "artgallery", "pixelcage",
             "abstract", "gallery", "abstractartgallery", "rainbow", "painting"):
    for form in (word, word.upper(), word.title(), word.replace(" ", "")):
        candidates.add(form)

for seq in (SEQ, SEQ[::-1], "12345612", "13524613", "51236451",
            "abcdefgh", "hgfedcba", "twzcfilo", "(.4:@FLR"):
    candidates |= {seq, seq.lower(), seq.upper()}

with ZipFile(IMAGE) as archive:
    tried = 0
    for password in sorted(candidates):
        tried += 1
        try:
            data = archive.read("secret.txt", pwd=password.encode("utf-8"))
        except Exception:
            continue
        print(f"PASSWORD FOUND: {password!r}")
        print(f"SECRET.TXT: {data.decode(errors='replace')!r}")
        break
    else:
        print(f"No match across {tried} geometry/color mapping candidates.")
