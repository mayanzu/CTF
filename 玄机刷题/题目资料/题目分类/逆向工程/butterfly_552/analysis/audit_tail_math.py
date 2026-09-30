from pathlib import Path
from itertools import product
root=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\butterfly_552\analysis\extracted')
ct=(root/'encode.dat').read_bytes(); k=(root/'encode.dat.key').read_bytes()[:8]
target=ct[32:36]
mask=(1<<64)-1
def enc(p):
 assert len(p)==8
 z=bytes(p[i]^k[i] for i in range(8))
 sw=bytes(z[i^1] for i in range(8))
 q=int.from_bytes(sw,'little')
 q=((q<<1)|(q>>63))&mask
 r=q.to_bytes(8,'little')
 return bytes((r[i]+k[i])&255 for i in range(8))
# Invert only the information actually present in the last four ciphertext bytes.
x=[(target[i]-k[i])&255 for i in range(4)]
p0=((x[1]>>1)|((x[2]&1)<<7))^k[0]
p1=((x[0]>>1)|((x[1]&1)<<7))^k[1]
p3=((x[2]>>1)|((x[3]&1)<<7))^k[3]
p2_options=tuple((((x[3]>>1)|((u&1)<<7))^k[2]) for u in (0,1))
print('ciphertext size:',len(ct),'tail offset:',len(ct)-4,'target:',target.hex())
print('tail keyed bytes X[0:4]:',bytes(x).hex())
print('inverse constraints, independent of missing ciphertext bytes X[4:8]:')
print('P[0]=',f'{p0:02x}',repr(bytes([p0])))
print('P[1]=',f'{p1:02x}',repr(bytes([p1])))
print('P[2] options=',','.join(f'{v:02x}' for v in p2_options),'(depends on unobserved X[4].bit0)')
print('P[3]=',f'{p3:02x}',repr(bytes([p3])))
print('expected final four bytes under recovered prefix: three ASCII hex digits followed by 0x7d')
print('necessary-format violations: P[0] must be hex digit, P[3] must be 0x7d; recovered values are',hex(p0),hex(p3))
chars=b'0123456789abcdefABCDEF'
hits=[]
for suffix in product(chars, repeat=3):
 plain4=bytes(suffix)+b'}'
 for p6_msb in (0,0x80):
  # File length is 36; main appends 24 00 at n,n+1. The last two bytes
  # of the malloc buffer (n+2,n+3) are uninitialized; P[6].MSB is tested.
  block=plain4+bytes([len(ct)&255,(len(ct)>>8)&255,p6_msb,0])
  out=enc(block)[:4]
  if out==target:
   hits.append((plain4,p6_msb,block.hex(),enc(block).hex()))
print('buffer tail framing model: [candidate suffix 4][n low][n high][uninitialized n+2][uninitialized n+3]')
print('program-inserted footer:',bytes([len(ct)&255,(len(ct)>>8)&255]).hex())
print('enumeration alphabet:',chars.decode())
print('candidate suffixes tested:',len(chars)**3)
print('P[6] high-bit cases tested: 0, 1; its lower 7 bits do not affect C[0]')
print('P[7] held at 00; it cannot affect C[0:4] because pair-swap maps w[7]=z[6]')
print('exact visible-byte forward matches:',len(hits))
for h in hits: print(h)
# Demonstrate the incomplete candidate and the impact of P[6].MSB on C[0].
partial4=bytes([p0,p1,p2_options[0],p3])
for p6_msb in (0,0x80):
 block=partial4+bytes([len(ct)&255,(len(ct)>>8)&255,p6_msb,0])
 print('inverse binary tail:',partial4.hex(),'P6.msb=',int(bool(p6_msb)),'forward first4=',enc(block)[:4].hex(),'match=',enc(block)[:4]==target)
print('dependency: after adjacent-byte swap, w[7]=z[6]; ROL64 wraps w[7].bit7 into output byte 0.bit0. Thus C[0] depends on P[6].bit7, and C[1:4] on P[0:3]. P[7] does not affect these written bytes.')
