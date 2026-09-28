from pathlib import Path
from zipfile import ZipFile
import hashlib

IMAGE = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
OUTERS = [Path(str(Path(__file__).resolve().parents[1] / '附件' / '像素囚笼附件.zip')),
          Path(str(Path(__file__).resolve().parents[1] / '附件' / '像素囚笼附件 (1).zip'))]
candidates=set()
for path in OUTERS:
    data=path.read_bytes()
    with ZipFile(path) as outer:
        for info in outer.infolist():
            for value in (info.CRC,info.file_size,info.compress_size,info.header_offset):
                candidates.update({str(value),hex(value)[2:],hex(value)[2:].upper(),
                                   f"{value:08x}",f"{value:08X}"})
                candidates.add(str(value)[::-1])
    digest=hashlib.sha256(data).hexdigest()
    for n in (8,12,16,20,24,32,40,48,64):
        candidates.add(digest[:n]); candidates.add(digest[-n:])
    candidates.add(str(len(data)))
    candidates.add(path.name)
    candidates.add(path.stem)
    candidates.add(hashlib.md5(data).hexdigest())
    candidates.add(hashlib.sha1(data).hexdigest())

with ZipFile(IMAGE) as archive:
    for password in sorted(candidates):
        try:
            plain=archive.read("secret.txt",pwd=password.encode("utf-8"))
        except Exception:
            continue
        print("PASSWORD FOUND:",repr(password))
        print("SECRET.TXT:",plain.decode(errors="replace"))
        break
    else:
        print(f"No match across {len(candidates)} outer ZIP CRC/hash/size candidates.")
