from pathlib import Path
from zipfile import ZipFile
import hashlib,base64
p=Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
bases=['12345612','13524613','BRYGPCBR','brygpcbr','(.4:@FLR','4046525864707682','15634215','51236451','ABCDEFAB']
candidates=set()
for s in bases:
 for raw in (s.encode(),bytes.fromhex(s) if len(s)%2==0 and all(c in '0123456789abcdefABCDEF' for c in s) else s.encode()):
  candidates.update([hashlib.md5(raw).hexdigest(),hashlib.sha1(raw).hexdigest(),hashlib.sha256(raw).hexdigest(),base64.b64encode(raw).decode(),raw.hex()])
with ZipFile(p) as z:
 print('derived hash/base64/hex candidates:',len(candidates))
 for pw in sorted(candidates):
  try:
   data=z.read('secret.txt',pwd=pw.encode())
   print('PASSWORD FOUND:',repr(pw)); print(data.decode(errors='replace')); break
  except Exception: pass
 else: print('No hash/base64/hex transform matched.')
