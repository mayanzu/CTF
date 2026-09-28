from pathlib import Path
from zipfile import ZipFile
archive=Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
candidates=Path('pixel_cage_numeric_header_matches.txt').read_text().splitlines()
print('header matches:',len(candidates))
with ZipFile(archive) as z:
    for password in candidates:
        try:
            plain=z.read('secret.txt',pwd=password.encode())
            print('PASSWORD FOUND:',password)
            print('SECRET.TXT:',plain.decode(errors='replace'))
            break
        except Exception:
            continue
    else:
        print('No decimal password of lengths 1..8 matched.')
