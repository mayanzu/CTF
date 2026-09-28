import base64
import hashlib
import re
import zlib
from pathlib import Path

abc=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\OpenHarmony_arkt_559\附件解包\HAP内容\ets\modules.abc').read_bytes()
raw=bytes.fromhex('138c5ff4280f930c0f3c15e8bb72bcb6f8e11c70ecaf0f724fe48a4e082359d4294eeae4')

def rc4(key,data):
 s=list(range(256));j=0
 for i in range(256):
  j=(j+s[i]+key[i%len(key)])&255;s[i],s[j]=s[j],s[i]
 i=j=0;out=bytearray()
 for b in data:
  i=(i+1)&255;j=(j+s[i])&255;s[i],s[j]=s[j],s[i]
  out.append(b^s[(s[i]+s[j])&255])
 return bytes(out)

seeds=set(re.findall(rb'[\x20-\x7e]{2,64}',abc))
seeds.update([b'OHCTF2025',b'OHCTF2026',b'OpenHarmony',b'OHCTF',b'flag',b'arkt',b'271',b'277',b'42583',b'75067'])
keys=set()
for seed in seeds:
 candidates={seed,seed.lower(),seed.upper(),seed.title(),seed[::-1],seed.swapcase()}
 try:candidates.add(seed.decode('ascii').encode('rot_13'))
 except Exception:pass
 for x in list(candidates):
  keys.add(x)
  keys.add(hashlib.md5(x).digest());keys.add(hashlib.md5(x).hexdigest().encode())
  keys.add(hashlib.sha1(x).digest());keys.add(hashlib.sha1(x).hexdigest().encode())
  keys.add(hashlib.sha256(x).digest());keys.add(hashlib.sha256(x).hexdigest().encode())
  keys.add(base64.b64encode(x))
  try:
   decoded=base64.b64decode(x+b'='*((-len(x))%4),validate=False)
   if decoded:keys.add(decoded)
  except Exception:pass
  keys.add(x.hex().encode())
  keys.add(str(zlib.crc32(x)).encode())
keys={k for k in keys if k}
prefixes=[b'OHCTF2025{',b'OHCTF2026{',b'flag{',b'FLAG{',b'OpenHarmony{']
print('ASCII_CONSTANT_SEEDS=',len(seeds))
print('DERIVED_RC4_KEY_CANDIDATES=',len(keys))
hits=[]
for key in keys:
 plain=rc4(key,raw)
 printable=sum(32<=b<127 for b in plain)/len(plain)
 if printable>=0.82 or any(plain.startswith(p) for p in prefixes):
  print(f'HIT key={key!r} printable={printable:.3f} plain={plain!r} sha256={hashlib.sha256(plain).hexdigest()}')
  hits.append((key,plain))
print('HITS=',len(hits))
