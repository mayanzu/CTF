import hashlib
import re
from pathlib import Path

abc=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\OpenHarmony_arkt_559\附件解包\HAP内容\ets\modules.abc').read_bytes()
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

strings=[]
for m in re.finditer(rb'[\x20-\x7e]{2,64}',abc):
    s=m.group()
    if s not in strings:
        strings.append(s)
print('ASCII_RUN_KEY_CANDIDATE_COUNT=',len(strings))
print('EXPECTED_PREFIXES=OHCTF2025{, OHCTF2026{, flag{, FLAG{, OpenHarmony{')
hits=[]
for key in strings:
    plain=rc4(key,raw)
    printable=sum(32<=b<127 for b in plain)/len(plain)
    if printable>=0.82 or any(plain.startswith(p) for p in [b'OHCTF2025{',b'OHCTF2026{',b'flag{',b'FLAG{',b'OpenHarmony{']):
        print(f'KEY_CANDIDATE={key!r} printable={printable:.3f} plain={plain!r} sha256={hashlib.sha256(plain).hexdigest()}')
        hits.append((key,plain))
print('HIGH_PRINTABLE_HITS=',len(hits))
print('ALL_ASCII_RUNS_LENGTH_2_TO_24:')
for s in strings:
    if 2<=len(s)<=24:
        print(repr(s))
