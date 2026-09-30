import base64
import hashlib
import itertools
import string

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

seeds=['OHCTF2025','OHCTF2026','OpenHarmony','openHarmony','OpenHarmony2025','OpenHarmony2026','OHCTF','OHOS','HarmonyOS','Harmony','Ark','ArkTS','arkt','secret','secretKey','flag','FLAG','CTF','2025','2026','271','277','7','42583','75067','74520','271277','OHCTF2025{','OHCTF2026{','OpenHarmony{','flag{']
keys=set()
for s in seeds:
 variants={s,s.lower(),s.upper(),s.title(),s[::-1],s.swapcase()}
 try: variants.add(s.encode().decode('rot_13'))
 except Exception: pass
 for v in list(variants):
  keys.add(v.encode())
  keys.add(base64.b64encode(v.encode()))
  keys.add(base64.b64encode(v.encode()).rstrip(b'='))
  keys.add(v.encode().hex().encode())
for n in [3,5,7,11,13,17,19,23,31,37,257,271,277,42583,65537,74520,75067]:
 for width in [1,2,4,8]:
  try:
   keys.add(n.to_bytes(width,'little'))
   keys.add(n.to_bytes(width,'big'))
  except OverflowError: pass
 keys.add(str(n).encode())
# Pairwise combinations of common seed words and years.
for a,b in itertools.product(seeds,seeds):
 if a!=b and len(a)+len(b)<=24:
  for sep in ['', '_', '-', ':', '.']:
   keys.add((a+sep+b).encode())
keys={k for k in keys if k}
prefixes=[b'OHCTF2025{',b'OHCTF2026{',b'flag{',b'FLAG{',b'OpenHarmony{']
hits=[]
print('GENERATED_KEY_COUNT=',len(keys))
for key in keys:
 plain=rc4(key,raw)
 printable=sum(32<=b<127 for b in plain)/len(plain)
 if printable>=0.82 or any(plain.startswith(p) for p in prefixes):
  print(f'HIT key={key!r} printable={printable:.3f} plaintext={plain!r} sha256={hashlib.sha256(plain).hexdigest()}')
  hits.append((key,plain))
print('HIGH_PRINTABLE_OR_PREFIX_HITS=',len(hits))
