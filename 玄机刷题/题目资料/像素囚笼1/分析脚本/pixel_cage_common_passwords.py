from itertools import product
from pathlib import Path
from zipfile import ZipFile

IMAGE = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
words = [
    "password", "passwd", "pass", "secret", "secretfile", "zip", "unzip", "open",
    "flag", "test", "testflag", "admin", "root", "toor", "qwerty", "letmein",
    "welcome", "iloveyou", "abc123", "123456", "1234567", "12345678", "000000",
    "ctf", "challenge", "misc", "stego", "steganography", "image", "picture",
    "pixel", "pixels", "cage", "pixelcage", "pixel_cage", "pixel-cage", "gallery",
    "art", "abstract", "abstractart", "artgallery", "abstractartgallery", "abstractartgallery",
    "color", "colors", "colour", "colours", "rainbow", "google", "googlecolor",
    "googlecolors", "material", "materialdesign", "blue", "red", "yellow", "green",
    "purple", "cyan", "xj", "xuanji", "edisec", "anwang", "anwangbei", "2026anwangbei",
    "xiangsu", "qiulong", "mima", "test123", "flag123", "secret123", "password123",
]
suffixes = ["", "1", "01", "123", "1234", "123456", "2026", "20260921", "583", "!", "@"]
prefixes = ["", "2026", "xj", "ctf", "flag", "pixel", "secret"]
candidates = set()
for word in words:
    forms = {word, word.lower(), word.upper(), word.title(), word.capitalize()}
    for form in forms:
        candidates.add(form)
        for suffix in suffixes:
            candidates.add(form + suffix)
        for prefix in prefixes:
            candidates.add(prefix + form)
        for prefix, suffix in product(prefixes, suffixes):
            candidates.add(prefix + form + suffix)
            candidates.add(prefix + "_" + form + "_" + suffix if suffix else prefix + "_" + form)

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
        print(f"No match across {len(candidates)} common/theme/event password variants.")
