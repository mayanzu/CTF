from pathlib import Path
from zipfile import ZipFile
p=Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
words=['xj2026','xj_2026','xj2026!','xj.edisec.net','edisec2026','edusec2026','2026anwangbei','anwang2026','anwangbei2026','安网杯','安网杯2026','2026安网杯','像素囚笼2026','玄机','玄机2026','玄机平台','2026MISC','misc2026','flag2026','secret2026']
with ZipFile(p) as z:
 for s in words:
  try:
   data=z.read('secret.txt',pwd=s.encode('utf-8'))
   print('PASSWORD FOUND:',repr(s)); print(data.decode(errors='replace')); break
  except Exception as exc: print('rejected:',repr(s),type(exc).__name__)
 else: print('No event/platform name candidate matched.')
