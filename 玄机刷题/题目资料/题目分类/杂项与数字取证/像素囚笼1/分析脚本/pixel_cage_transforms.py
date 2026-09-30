from pathlib import Path
from zipfile import ZipFile
p=Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
candidates=[
 '2023262932353841','20-23-26-29-32-35-38-41','218257163218','2-18-25-7-16-3-2-18',
 'blue-red-yellow-green-purple-cyan-blue-red','B-R-Y-G-P-C-B-R','blue_red_yellow_green_purple_cyan_blue_red',
 'BG-RP-YC','bluegreenredpurpleyellowcyan','BLUEGREENREDPURPLEYELLOWCYAN',
 "'+/8<@KO",')19<DLMU',"',16;@KP",')07>ELMT',
]
with ZipFile(p) as z:
 for pw in candidates:
  try:
   data=z.read('secret.txt',pwd=pw.encode())
   print('PASSWORD FOUND:',repr(pw)); print(data.decode(errors='replace')); break
  except Exception as exc: print('rejected:',repr(pw),type(exc).__name__)
 else: print('No geometry/color-transformed candidate matched.')
