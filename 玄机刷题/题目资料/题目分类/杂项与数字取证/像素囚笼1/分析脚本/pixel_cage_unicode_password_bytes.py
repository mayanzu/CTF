from pathlib import Path
from zipfile import ZipFile
p=Path(r'D:\Downloads\像素囚笼附件 (1)\challenge.png')
words=['蓝红黄绿紫青蓝红','蓝绿红紫黄青','蓝红黄绿紫青','蓝色红色黄色绿色紫色青色蓝色红色','红橙黄绿蓝紫','像素囚笼','像素囚笼1','抽象艺术画廊','抽象艺术画廊2026','美术馆','画廊']
encodings=['utf-8','utf-8-sig','gbk','gb18030','big5','utf-16le','utf-16be','utf-32le','utf-32be']
candidates={}
for w in words:
 for enc in encodings:
  try:
   b=w.encode(enc)
   candidates.setdefault(b,[]).append((w,enc))
   if enc.startswith('utf-16') or enc.startswith('utf-32'):
    candidates.setdefault(b'\xff\xfe'+b,[]).append((w,enc+'+LE-BOM'))
    candidates.setdefault(b'\xfe\xff'+b,[]).append((w,enc+'+BE-BOM'))
  except UnicodeEncodeError: pass
print('distinct encoded byte candidates:',len(candidates),'source strings:',len(words),'encodings:',encodings)
with ZipFile(p) as z:
 for pwd,origins in candidates.items():
  try:
   data=z.read('secret.txt',pwd=pwd)
   print('PASSWORD FOUND:',repr(pwd),'origins:',origins,'secret:',data.decode(errors='replace'));break
  except Exception:pass
 else:print('No Chinese phrase matched under UTF-8/GBK/GB18030/Big5/UTF-16/UTF-32 encodings.')
