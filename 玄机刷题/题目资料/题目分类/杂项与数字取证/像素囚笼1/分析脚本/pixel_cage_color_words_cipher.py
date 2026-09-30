from pathlib import Path
from zipfile import ZipFile
import string

IMAGE = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
alpha = string.ascii_lowercase
seqs = ["blueredyellowgreenpurplecyanbluered",
        "bluegreenredpurpleyellowcyan",
        "brygpcbr", "bgrpyc"]
keys = ["abstract", "artgallery", "gallery", "pixelcage",
        "12345612", "13524613", "51236451", "abcdefgh"]
candidates = set()

def shift(s,n):
    return "".join(chr(97+(ord(c)-97+n)%26) if c.isalpha() else c for c in s.lower())

def vig(s,k,mode):
    out=[]; j=0
    for c in s.lower():
        if not c.isalpha(): continue
        a=ord(c)-97; q=k[j%len(k)]; b=(int(q)%26 if q.isdigit() else ord(q.lower())-97)
        out.append(chr(97+((a+b)%26 if mode==0 else (a-b)%26 if mode==1 else (b-a)%26)))
        j+=1
    return "".join(out)

for base in seqs:
    for sep in ("", " ", "-", "_", ".", ","):
        for words in (["blue","red","yellow","green","purple","cyan","blue","red"],
                      ["blue","green","red","purple","yellow","cyan"]):
            raw=sep.join(words)
            for s in (raw,raw.replace(sep,""),raw[::-1]):
                candidates.add(s)
                candidates.add(s.upper())
                candidates.add(s.title())
                for n in range(26):
                    candidates.add(shift(s,n))
                    candidates.add(shift(s,n).upper())
                candidates.add(s.translate(str.maketrans(alpha,alpha[::-1])))
                candidates.add(s.translate(str.maketrans(alpha,alpha[::-1])).upper())
                for key in keys:
                    for mode in (0,1,2):
                        candidates.add(vig(s,key,mode))

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
        print(f"No match across {len(candidates)} full color-word cipher candidates.")
