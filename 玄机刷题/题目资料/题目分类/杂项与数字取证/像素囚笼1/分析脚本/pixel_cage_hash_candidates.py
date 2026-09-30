from pathlib import Path
from zipfile import ZipFile
from PIL import Image
import hashlib,base64
p=Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
raw=p.read_bytes(); pix=Image.open(p).convert('RGB').tobytes()
seeds=['Abstract Art Gallery','abstractartgallery','BRYGPCBR','12345612','13524613','51236451','1121311222321121','(.4:@FLR','challenge.png','2026安网杯-像素囚笼1','像素囚笼1','Pixel Cage','Pixel Prison','RGB','512x512','512512']
seeds += [raw.hex(),pix.hex()]
candidates=set()
for s in seeds:
 for b in (s.encode('utf-8'),):
  candidates.update([hashlib.md5(b).hexdigest(),hashlib.sha1(b).hexdigest(),hashlib.sha256(b).hexdigest(),hashlib.sha512(b).hexdigest()])
for b in (raw,pix): candidates.update([hashlib.md5(b).hexdigest(),hashlib.sha1(b).hexdigest(),hashlib.sha256(b).hexdigest(),hashlib.sha512(b).hexdigest()])
print('hash-derived candidates:',len(candidates))
with ZipFile(p) as z:
 for pw in candidates:
  try:
   data=z.read('secret.txt',pwd=pw.encode())
   print('PASSWORD FOUND:',pw);print(data.decode(errors='replace'));break
  except Exception: pass
 else: print('No image/text hash candidate matched.')
