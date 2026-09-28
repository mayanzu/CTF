from pathlib import Path
from zipfile import ZipFile
archive=Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
candidates=Path('pixel_cage_ascii_header_matches.txt').read_bytes().splitlines()
print('header matches:',len(candidates))
with ZipFile(archive) as z:
 for raw in candidates:
  try:
   plain=z.read('secret.txt',pwd=raw)
   print('PASSWORD FOUND:',repr(raw.decode('ascii')))
   print('SECRET.TXT:',plain.decode(errors='replace'))
   break
  except Exception: pass
 else: print('No printable ASCII password of lengths 1..4 matched.')
