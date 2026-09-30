import base64
import hashlib
import string

TOKENS='''ndG5nZa= nte3ndK= nJy2nJi= mtK0mJG= nde5mZK= nJG4mW== mJu4nti= mJq4ndK= nJG4mW== mJa0mZG= nJaXma== mta5nZa= mta4nta= mZa2ndG= mJy1ntm= mZiYmJC= mJy5ntq= odqXmG== mta1otC= nJyZndq= nZaYotq= ndq0odK= nJG4mW== mZa2ndG= nJaZmq== mtK0nJa= ndy5ndu= mJmZma== nZaZndm= ndy3nZG= nJe4mta= ndaZnde= nZm3ndy= mJmZma== nJyYmJe= mtK0nJa='''.split()
STD='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
CUSTOM='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/'
C=[int(base64.b64decode(s.translate(str.maketrans(CUSTOM,STD)))) for s in TOKENS]
n,p,q,e,d=75067,271,277,7,42583
raw=bytes(pow(c,d,n) for c in C)
assert all(pow(m,e,n)==c for m,c in zip(raw,C))
print(f'PARAMETERS n={n} p={p} q={q} phi={(p-1)*(q-1)} e={e} d={d}')
print('RSA_DECRYPTED_HEX=',raw.hex())
print('RSA_DECRYPTED_REPR=',repr(raw))
print('ROUNDTRIP_ALL_36=',all(pow(m,e,n)==c for m,c in zip(raw,C)))

def rc4(key,data):
    key=key if isinstance(key,bytes) else key.encode()
    s=list(range(256));j=0
    for i in range(256):
        j=(j+s[i]+key[i%len(key)])&255;s[i],s[j]=s[j],s[i]
    i=j=0;out=bytearray()
    for b in data:
        i=(i+1)&255;j=(j+s[i])&255;s[i],s[j]=s[j],s[i]
        out.append(b^s[(s[i]+s[j])&255])
    return bytes(out)
keys=['OHCTF2025','OHCTF2026','OpenHarmony','openHarmony','OpenHarmony2025','OpenHarmony2026','OHCTF','ark','arkt','Ark','ArkTS','arkts','secret','secretKey','secretkey','12345678','2025','2026','flag','FLAG','CTF','CTF2025','OHOS','HarmonyOS','Harmony','OpenHarmonyCTF','OHCTF2025!','OHCTF2026!']
for key in keys:
    plain=rc4(key,raw)
    printable=sum(32<=b<127 or b in (9,10,13) for b in plain)/len(plain)
    print(f'KEY={key!r} printable={printable:.2f} plain={plain!r}')
