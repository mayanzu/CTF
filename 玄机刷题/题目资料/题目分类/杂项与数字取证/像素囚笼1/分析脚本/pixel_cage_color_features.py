from collections import Counter
from pathlib import Path
from zipfile import ZipFile
import colorsys
import hashlib

IMAGE = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
seq = ["blue", "red", "yellow", "green", "purple", "cyan", "blue", "red"]
rgb = {
    "blue": (66, 133, 244), "red": (219, 68, 55), "yellow": (244, 180, 0),
    "green": (15, 157, 88), "purple": (171, 71, 188), "cyan": (0, 172, 193),
}
features = {}
for name, color in rgb.items():
    r, g, b = color
    h, s, v = colorsys.rgb_to_hsv(r / 255, g / 255, b / 255)
    nums = [ord(ch) - 96 for ch in name]
    features[name] = {
        "length": len(name), "vowels": sum(ch in "aeiou" for ch in name),
        "consonants": sum(ch not in "aeiou" for ch in name),
        "first": nums[0], "last": nums[-1], "a1z26sum": sum(nums),
        "asciisum": sum(map(ord, name)), "red": r, "green": g, "blue": b,
        "rgbsum": r + g + b, "rgbxor": r ^ g ^ b,
        "hue_deg": round(h * 360), "hue_sector": round(h * 6),
        "sat_pct": round(s * 100), "value_pct": round(v * 100),
    }

candidates = set()
for feature in next(iter(features.values())):
    values = [features[c][feature] for c in seq]
    for sep in ("", "-", "_", ",", ".", " "):
        candidates.add(sep.join(map(str, values)))
        candidates.add(sep.join(f"{x:02d}" for x in values))
    # A1Z26/modular interpretations of feature values.
    for modulus in (10, 26):
        for offset in range(modulus):
            mapped = [(v + offset) % modulus for v in values]
            candidates.add("".join(map(str, mapped)))
            if modulus == 26:
                candidates.add("".join(chr(97 + v) for v in mapped))
                candidates.add("".join(chr(65 + v) for v in mapped))
    for base in ("".join(map(str, values)), ",".join(map(str, values)),
                 "-".join(map(str, values)), "_".join(map(str, values))):
        candidates.add(hashlib.md5(base.encode()).hexdigest())
        candidates.add(hashlib.sha1(base.encode()).hexdigest())

# The written color words themselves and simple acrostics.
for f in ("", "-", "_", " "):
    candidates.add(f.join(seq))
    candidates.add(f.join(name[0] for name in seq))
    candidates.add(f.join(name[-1] for name in seq))

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
        print(f"No match across {len(candidates)} color-name/RGB/HSV feature candidates.")
