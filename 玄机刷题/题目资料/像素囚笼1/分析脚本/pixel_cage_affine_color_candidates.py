from itertools import permutations
from pathlib import Path
from zipfile import ZipFile

IMAGE = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
SEQ = "BRYGPCBR"
COLORS = sorted(set(SEQ))
SIZES = [40, 46, 52, 58, 64, 70, 76, 82]
candidates = set()

# Every one-to-one color numbering, followed by numeric or alphabetic Caesar
# offsets. Include both 0/1-based alphabet conventions and letter case.
for order in permutations(COLORS):
    code = {color: i for i, color in enumerate(order)}
    nums = [code[c] for c in SEQ]
    for offset in range(10):
        candidates.add("".join(str((n + offset) % 10) for n in nums))
        candidates.add("".join(str((n + offset) % 10) for n in nums).lstrip("0"))
    for offset in range(26):
        letters = "".join(chr(97 + (n + offset) % 26) for n in nums)
        candidates.add(letters)
        candidates.add(letters.upper())

# Initials under all Caesar shifts, including Atbash equivalents.
for offset in range(26):
    for base in (SEQ, SEQ[::-1]):
        candidates.add("".join(chr(97 + (ord(c.lower()) - 97 + offset) % 26) for c in base))

# Map measured diameters/radii into A1Z26 with all possible baselines and shifts.
for values in (SIZES, [v // 2 for v in SIZES], list(range(1, 9))):
    for baseline in range(min(values) - 2, max(values) + 3):
        raw = [v - baseline for v in values]
        for shift in range(26):
            candidates.add("".join(chr(97 + (v + shift) % 26) for v in raw))
            candidates.add("".join(chr(65 + (v + shift) % 26) for v in raw))

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
        print(f"No match across {len(candidates)} color-shift/size-baseline candidates.")
