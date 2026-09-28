from itertools import permutations
from pathlib import Path
from zipfile import ZipFile

IMAGE = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
SEQ = "BRYGPCBR"
COLORS = sorted(set(SEQ))
DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz"
candidates = set()

def repr_num(n):
    if n == 0:
        return "0"
    out = ""
    while n:
        n, r = divmod(n, 36)
        out = DIGITS[r] + out
    return out

for order in permutations(COLORS):
    for start, base in ((0, 6), (1, 7)):
        mapping = {c: i + start for i, c in enumerate(order)}
        vals = [mapping[c] for c in SEQ]
        for radix in range(max(vals) + 1, 37):
            n = 0
            for v in vals:
                n = n * radix + v
            forms = {str(n), repr_num(n), format(n, "x"), format(n, "X"),
                     format(n, "o"), format(n, "b")}
            for form in forms:
                candidates.add(form)
                candidates.add(form.upper())
                candidates.add(form[::-1])
            byte_len = max(1, (n.bit_length() + 7) // 8)
            raw = n.to_bytes(byte_len, "big")
            candidates.add(raw.decode("latin1"))
            candidates.add(raw.hex())
            candidates.add(raw.hex().upper())
            for order2 in (raw, raw[::-1]):
                try:
                    candidates.add(order2.decode("ascii"))
                except UnicodeDecodeError:
                    pass

# Circle size ranks form another 8-symbol numeral; combine color and size into
# a 6-bit value and interpret the eight values as one big-endian integer.
for order in permutations(COLORS):
    mapping = {c: i for i, c in enumerate(order)}
    color_ids = [mapping[c] for c in SEQ]
    for size_offset in (0, 1):
        for rev in (False, True):
            size = list(range(8))
            if rev: size.reverse()
            size = [(v + size_offset) % 8 for v in size]
            vals = [(c << 3) | s for c, s in zip(color_ids, size)]
            n = 0
            for v in vals:
                n = n * 64 + v
            for form in (str(n), repr_num(n), format(n, "x"), format(n, "X"), format(n, "b")):
                candidates.add(form)
                candidates.add(form[::-1])

with ZipFile(IMAGE) as archive:
    for password in sorted(candidates):
        try:
            data = archive.read("secret.txt", pwd=password.encode("latin1"))
        except Exception:
            continue
        print(f"PASSWORD FOUND: {password!r}")
        print(f"SECRET.TXT: {data.decode(errors='replace')!r}")
        break
    else:
        print(f"No match across {len(candidates)} radix-converted sequence candidates.")
