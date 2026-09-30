import base64
import hashlib

TOKENS='''ndG5nZa= nte3ndK= nJy2nJi= mtK0mJG= nde5mZK= nJG4mW== mJu4nti= mJq4ndK= nJG4mW== mJa0mZG= nJaXma== mta5nZa= mta4nta= mZa2ndG= mJy1ntm= mZiYmJC= mJy5ntq= odqXmG== mta1otC= nJyZndq= nZaYotq= ndq0odK= nJG4mW== mZa2ndG= nJaZmq== mtK0nJa= ndy5ndu= mJmZma== nZaZndm= ndy3nZG= nJe4mta= ndaZnde= nZm3ndy= mJmZma== nJyYmJe= mtK0nJa='''.split()
STD='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
CUSTOM='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/'
C=[int(base64.b64decode(s.translate(str.maketrans(CUSTOM,STD)))) for s in TOKENS]
n=75067;e=7;d=42583

def rc4(key,data):
 key=key.encode() if isinstance(key,str) else key
 s=list(range(256));j=0
 for i in range(256):
  j=(j+s[i]+key[i%len(key)])&255;s[i],s[j]=s[j],s[i]
 i=j=0;out=bytearray()
 for b in data:
  i=(i+1)&255;j=(j+s[i])&255;s[i],s[j]=s[j],s[i]
  out.append(b^s[(s[i]+s[j])&255])
 return bytes(out)

print('N=',n,'E=',e,'D=',d)
for label,exponent in [('pow_e',e),('pow_d',d)]:
 vals=[pow(c,exponent,n) for c in C]
 print(f'{label}_VALUES=',vals)
 print(f'{label}_BYTE_RANGE=',min(vals),max(vals),'all_0_255=',all(0<=x<256 for x in vals))
 if all(0<=x<256 for x in vals):
  data=bytes(vals)
  print(f'{label}_HEX=',data.hex())
  print(f'{label}_SHA256=',hashlib.sha256(data).hexdigest())
  for key in ['OHCTF2025','OHCTF2026','ohctf2025','ohctf2026','OpenHarmony','openHarmony','secretKey','secret','flag','ARKT','arkt']:
   plain=rc4(key,data)
   if sum(32<=b<127 for b in plain)/len(plain)>0.7 or b'{' in plain:
    print(f'{label}_KEY_HIT key={key!r} plain={plain!r}')
