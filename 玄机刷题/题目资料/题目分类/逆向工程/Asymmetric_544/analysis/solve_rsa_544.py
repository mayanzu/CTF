import pathlib,struct,sys,math
from sympy import factorint, isprime
exe=pathlib.Path(sys.argv[1]) if len(sys.argv)>1 else pathlib.Path(__file__).resolve().parents[1]/'extracted'/'Asymmetric_flag.exe'
b=exe.read_bytes(); u32=lambda o:struct.unpack_from('<I',b,o)[0]
pe=u32(0x3c); sh=pe+24+struct.unpack_from('<H',b,pe+20)[0]; sections=[]
for j in range(struct.unpack_from('<H',b,pe+6)[0]):
 s=sh+40*j; name=b[s:s+8].split(b'\0')[0].decode(); vs,va,rs,rp=struct.unpack_from('<IIII',b,s+8); sections.append((name,va,max(vs,rs),rp))
def vaoff(va):
 rva=va-0x400000
 for name,va0,size,rp in sections:
  if va0<=rva<va0+size:return rp+rva-va0
 raise ValueError(f'unmapped VA {va:#x}')
n=int(b[vaoff(0x4cb69e):vaoff(0x4cb69e)+36].decode('ascii'))
y=int(b[vaoff(0x4cb405):vaoff(0x4cb405)+35].decode('ascii'))
e=0x10001
print('static modulus n=',n)
print('expected decimal output y=',y)
print('public exponent e=',e)
assert y<n
factors=factorint(n); print('factorization=',factors)
assert math.prod(int(p)**k for p,k in factors.items())==n
print('factor product check=True')
print('factor primality=',{int(p):bool(isprime(p)) for p in factors})
assert all(isprime(p) for p in factors)
phi=math.prod(int(p)**(k-1)*(int(p)-1) for p,k in factors.items())
print('phi(n)=',phi)
print('gcd(e,phi)=',math.gcd(e,phi)); assert math.gcd(e,phi)==1
d=pow(e,-1,phi); print('private exponent d=',d)
m=pow(y,d,n); print('recovered integer m=',m, 'bits=',m.bit_length())
raw=m.to_bytes((m.bit_length()+7)//8,'big')
print('recovered bytes hex=',raw.hex())
print('recovered bytes=',raw)
print('forward modular verification=',pow(m,e,n)==y)
assert pow(m,e,n)==y
assert pow(int.from_bytes(raw,'big'),e,n)==y
print('candidate=',raw.decode('ascii'))
assert raw.decode('ascii').startswith('flag{') and raw.endswith(b'}')
