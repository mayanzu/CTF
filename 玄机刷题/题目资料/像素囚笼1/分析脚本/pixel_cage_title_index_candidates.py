from itertools import permutations
from pathlib import Path
from zipfile import ZipFile

IMAGE = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
names = ["blue", "red", "yellow", "green", "purple", "cyan", "blue", "red"]
title_strings = ["abstractartgallery", "abstractartgallery"[::-1], "abstract", "artgallery", "gallery", "abstractartgallery2026"]
diam = [40,46,52,58,64,70,76,82]
radius = [20,23,26,29,32,35,38,41]
rank = list(range(1,9))
cx = [80,135,190,245,300,355,410,465]
sx = [90,165,240,315,390,465,90,165]
sy = [110,250,390,110,250,390,110,250]
seqs = [diam,radius,rank,cx,sx,sy,[b-a for a,b in zip(cx,sx)],
        [b-420 for b in sy], [40,46,52,58,64,70,76,82]]
candidates=set()

# Use a circle's size/position as a modular index into its color name.
for vals in seqs:
    for scale in (1,2,3,4,5,6,10,20):
        scaled=[v//scale for v in vals]
        for offset in range(-2,9):
            for backwards in (False,True):
                out=[]
                for word,v in zip(names,scaled):
                    i=(v+offset)%len(word)
                    if backwards: i=len(word)-1-i
                    out.append(word[i])
                for s in ("".join(out),"".join(out).upper()):
                    candidates.add(s)

# Index title fragments with sizes, coordinates, and every one-to-one color index.
for title in title_strings:
    for vals in seqs:
        for scale in (1,2,3,4,5,6,10,20):
            scaled=[v//scale for v in vals]
            for offset in range(-2,9):
                candidates.add("".join(title[(v+offset)%len(title)] for v in scaled))
    for order in permutations(sorted(set("BRYGPC"))):
        mapping={c:i for i,c in enumerate(order)}
        color_ids=[mapping[c] for c in "BRYGPCBR"]
        for offset in range(-2,9):
            candidates.add("".join(title[(v+offset)%len(title)] for v in color_ids))

with ZipFile(IMAGE) as archive:
    for password in sorted(candidates):
        try:
            data=archive.read("secret.txt",pwd=password.encode("ascii"))
        except Exception:
            continue
        print(f"PASSWORD FOUND: {password!r}")
        print(f"SECRET.TXT: {data.decode(errors='replace')!r}")
        break
    else:
        print(f"No match across {len(candidates)} title/color-name index candidates.")
