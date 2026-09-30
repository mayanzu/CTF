import base64
import hashlib
import math
import re
from itertools import combinations

TOKENS = '''ndG5nZa= nte3ndK= nJy2nJi= mtK0mJG= nde5mZK= nJG4mW== mJu4nti= mJq4ndK= nJG4mW== mJa0mZG= nJaXma== mta5nZa= mta4nta= mZa2ndG= mJy1ntm= mZiYmJC= mJy5ntq= odqXmG== mta1otC= nJyZndq= nZaYotq= ndq0odK= nJG4mW== mZa2ndG= nJaZmq== mtK0nJa= ndy5ndu= mJmZma== nZaZndm= ndy3nZG= nJe4mta= ndaZnde= nZm3ndy= mJmZma== nJyYmJe= mtK0nJa='''.split()
STD='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
CUSTOM='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/'
TRANS=str.maketrans(CUSTOM,STD)
C=[int(base64.b64decode(s.translate(TRANS))) for s in TOKENS]
print('TOKEN_COUNT=',len(C))
print('CIPHERS=',C)
print('CIPHER_MIN_MAX=',min(C),max(C))

def primes_upto(n):
    sieve=bytearray(b'\x01')*(n+1)
    sieve[:2]=b'\x00\x00'
    for p in range(2,math.isqrt(n)+1):
        if sieve[p]:
            start=p*p
            sieve[start:n+1:p]=b'\x00'*(((n-start)//p)+1)
    return [i for i,v in enumerate(sieve) if v]

def rc4(key,data):
    key=key if isinstance(key,bytes) else key.encode()
    s=list(range(256)); j=0
    for i in range(256):
        j=(j+s[i]+key[i%len(key)])&255
        s[i],s[j]=s[j],s[i]
    i=j=0; out=bytearray()
    for b in data:
        i=(i+1)&255; j=(j+s[i])&255
        s[i],s[j]=s[j],s[i]
        out.append(b ^ s[(s[i]+s[j])&255])
    return bytes(out)

keys=['OHCTF2025','OHCTF2026','OpenHarmony','openHarmony','arkt','secretKey','secret','OHCTF']
prefixes=[b'OHCTF2025{',b'OHCTF2026{',b'flag{',b'FLAG{',b'OpenHarmony{']
max_n=2_000_000
primes=primes_upto(math.isqrt(max_n)+1)
exp_list=[3,5,7,11,13,17,19,23,31,37,257,65537]
print('SEARCH_N_RANGE=',max(C)+1,'..',max_n)
print('RSA_E_CANDIDATES=',exp_list)
seen=0
hits=[]
for ix,p in enumerate(primes):
    for q in primes[ix:]:
        n=p*q
        if n<=max(C):
            continue
        if n>max_n:
            break
        phi=(p-1)*(q-1)
        for e in exp_list:
            if math.gcd(e,phi)!=1:
                continue
            d=pow(e,-1,phi)
            raw=[]
            ok=True
            for c in C:
                m=pow(c,d,n)
                if m>255:
                    ok=False
                    break
                raw.append(m)
            if not ok:
                continue
            seen+=1
            encrypted=bytes(raw)
            print(f'BYTEWISE_RSA_CANDIDATE n={n} p={p} q={q} e={e} d={d} raw_sha256={hashlib.sha256(encrypted).hexdigest()} raw_hex={encrypted.hex()}')
            # The pre-RC4 bytes are expected to be an RC4 ciphertext. Verify candidate known key and CTF prefix.
            for key in keys:
                plain=rc4(key,encrypted)
                if any(plain.startswith(prefix) for prefix in prefixes) or (b'{' in plain[:16] and plain.endswith(b'}')):
                    roundtrip=[pow(x,e,n) for x in encrypted]
                    if roundtrip==C:
                        print(f'PLAINTEXT_HIT key={key!r} plain={plain!r} sha256={hashlib.sha256(plain).hexdigest()}')
                        hits.append((n,p,q,e,d,key,plain))
            # Also identify if bytes already have common marker, regardless of RC4.
            if any(encrypted.startswith(prefix) for prefix in prefixes):
                print(f'RAW_PREFIX_HIT raw={encrypted!r}')
print('BYTEWISE_CANDIDATE_COUNT=',seen)
print('VALID_FLAG_HIT_COUNT=',len(hits))
