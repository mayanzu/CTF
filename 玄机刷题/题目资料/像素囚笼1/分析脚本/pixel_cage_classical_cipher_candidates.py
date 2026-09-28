from itertools import product
from pathlib import Path
from zipfile import ZipFile

IMAGE = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
letters = "abcdefghijklmnopqrstuvwxyz"
seq = "brygpcbr"
base_words = ["abstract", "art", "gallery", "artgallery", "abstractartgallery",
              "pixel", "cage", "pixelcage", "google", "colors", "blue",
              "red", "yellow", "green", "purple", "cyan"]
keys = ["abstract", "artgallery", "gallery", "abstractartgallery",
        "pixelcage", "brygpc", "brygpcbr", "abcdef", "123456", "4285f4"]
candidates = set()

def caesar(s, n):
    return "".join(chr(97 + (ord(c) - 97 + n) % 26) if c.isalpha() else c for c in s.lower())

def vig(text, key, mode):
    out = []
    for i, ch in enumerate(text.lower()):
        if ch not in letters:
            continue
        a = ord(ch) - 97
        kch = key[i % len(key)]
        k = int(kch) % 26 if kch.isdigit() else ord(kch.lower()) - 97
        v = (a + k) % 26 if mode == "enc" else (a - k) % 26 if mode == "dec" else (k - a) % 26
        out.append(chr(97 + v))
    return "".join(out)

def rail(s, depth):
    rows = [""] * depth
    row, direction = 0, 1
    for c in s:
        rows[row] += c
        if row == 0: direction = 1
        elif row == depth - 1: direction = -1
        row += direction
    return "".join(rows)

texts = set(base_words + [seq, "abcdefab", "acebdfac", "12345612", "13524613", "51236451"])
for text in list(texts):
    for n in range(26):
        candidates.add(caesar(text, n))
    candidates.add(text[::-1])
    candidates.add(text.translate(str.maketrans(letters, letters[::-1])))
    for depth in (2, 3, 4):
        candidates.add(rail(text, depth))
        candidates.add(rail(text, depth)[::-1])
    for width in (2, 3, 4, 5, 6, 7, 8):
        candidates.add("".join(text[i::width] for i in range(width)))
        candidates.add("".join(text[i::width] for i in reversed(range(width))))
    for key in keys:
        for mode in ("enc", "dec", "beaufort"):
            candidates.add(vig(text, key, mode))

# Treat color indices as the Vigenere key and the image title/theme as source text.
color_keys = ["12345612", "13524613", "51236451", "01234501", "02413502"]
for text in texts:
    for key in color_keys:
        for mode in ("enc", "dec", "beaufort"):
            candidates.add(vig(text, key, mode))

# Basic columnar transposition using title words as keys.
for text in texts:
    for key in ("abstract", "gallery", "artgallery"):
        width = len(key)
        nrows = (len(text) + width - 1) // width
        padded = text.ljust(nrows * width, "x")
        order = sorted(range(width), key=lambda i: (key[i], i))
        enc = "".join("".join(padded[r * width + c] for r in range(nrows)) for c in order)
        candidates.add(enc)
        candidates.add(enc.rstrip("x"))

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
        print(f"No match across {len(candidates)} classical title/color transforms.")
