from itertools import permutations
from pathlib import Path
from zipfile import ZipFile
import base64

IMAGE = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
SEQ = "BRYGPCBR"
COLORS = sorted(set(SEQ))
ALPHABETS = [
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
]
candidates = set()

for order in permutations(COLORS):
    color = {c: i for i, c in enumerate(order)}
    ids = [color[c] for c in SEQ]
    for size_order in (list(range(8)), list(reversed(range(8)))):
        for size_offset in (0, 1):
            sizes = [(v + size_offset) % 8 for v in size_order]
            size_seq = [sizes[i] for i in range(8)]
            for first in ("color", "size"):
                for alphabet in ALPHABETS:
                    nums = [((a << 3) | b) if first == "color" else ((b << 3) | a)
                            for a, b in zip(ids, size_seq)]
                    if max(nums) >= 64:
                        continue
                    text = "".join(alphabet[v] for v in nums)
                    for form in (text, text[::-1]):
                        candidates.add(form.encode("ascii"))
                        try:
                            padded = form + "=" * ((-len(form)) % 4)
                            raw = base64.urlsafe_b64decode(padded)
                            candidates.add(raw)
                        except Exception:
                            pass

# Pack each color into three bits and each size into three bits, then split the
# 48-bit stream into six bytes. This is an alternate view of the same symbols.
for order in permutations(COLORS):
    color = {c: i for i, c in enumerate(order)}
    ids = [color[c] for c in SEQ]
    for size_offset in (0, 1):
        for reverse_sizes in (False, True):
            sizes = list(range(8))
            if reverse_sizes:
                sizes.reverse()
            sizes = [(v + size_offset) % 8 for v in sizes]
            stream = "".join(f"{a:03b}{b:03b}" for a, b in zip(ids, sizes))
            raw = int(stream, 2).to_bytes(6, "big")
            candidates.add(raw)
            candidates.add(base64.b64encode(raw))

with ZipFile(IMAGE) as archive:
    for password in sorted(candidates):
        try:
            data = archive.read("secret.txt", pwd=password)
        except Exception:
            continue
        print(f"PASSWORD FOUND (bytes): {password!r}")
        print(f"SECRET.TXT: {data.decode(errors='replace')!r}")
        break
    else:
        print(f"No match across {len(candidates)} base64/bit-packed color-size candidates.")
