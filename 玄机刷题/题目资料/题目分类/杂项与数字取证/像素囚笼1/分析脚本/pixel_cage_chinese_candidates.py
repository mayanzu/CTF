from pathlib import Path
from zipfile import ZipFile
p=Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
words=['蓝红黄绿紫青蓝红','蓝绿红紫黄青','蓝红黄绿紫青','蓝色红色黄色绿色紫色青色蓝色红色','红橙黄绿蓝紫','像素囚笼','像素囚笼1','抽象艺术画廊','抽象艺术画廊2026','美术馆','画廊']
with ZipFile(p) as z:
 for pw in words:
  try:
   data=z.read('secret.txt',pwd=pw.encode('utf-8'))
   print('PASSWORD FOUND:',repr(pw)); print(data.decode(errors='replace')); break
  except Exception as exc: print('rejected:',repr(pw),type(exc).__name__)
 else: print('No Chinese color/name candidate matched.')
