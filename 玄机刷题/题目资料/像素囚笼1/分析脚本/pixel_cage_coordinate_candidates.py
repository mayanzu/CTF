from pathlib import Path
from zipfile import ZipFile
p=Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
candidates=['1121311222321121','0010200111210010','11-21-31-12-22-32-11-21','1,1;2,1;3,1;1,2;2,2;3,2;1,1;2,1','12312312','11122211']
with ZipFile(p) as z:
 for pw in candidates:
  try:
   data=z.read('secret.txt',pwd=pw.encode())
   print('PASSWORD FOUND:',repr(pw)); print('SECRET.TXT:',data.decode(errors='replace')); break
  except Exception as exc: print('rejected:',repr(pw),type(exc).__name__)
 else: print('No 2x3 coordinate encoding matched.')
