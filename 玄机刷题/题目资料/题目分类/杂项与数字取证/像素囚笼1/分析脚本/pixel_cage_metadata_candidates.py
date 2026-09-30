from pathlib import Path
from zipfile import ZipFile
p=Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
candidates=['20260413103906','2026-04-13','20260413','103906','2026_04_13','2026-09-21','20260921','challengepng','challenge.png','secret.txt','image','colorfulart','abstract_art_gallery','Abstract_Art_Gallery','Abstract-Art-Gallery','Abstract Art Gallery','Gallery2026','gallery2026','pixel2026','pixel1','cage1','xj583']
with ZipFile(p) as z:
 for pw in candidates:
  try:
   data=z.read('secret.txt',pwd=pw.encode())
   print('PASSWORD FOUND:',repr(pw)); print(data.decode(errors='replace')); break
  except Exception as exc: print('rejected:',repr(pw),type(exc).__name__)
 else: print('No date, filename, or title-format candidate matched.')
