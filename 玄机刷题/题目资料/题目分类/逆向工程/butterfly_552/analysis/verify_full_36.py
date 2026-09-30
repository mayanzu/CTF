from pathlib import Path
import hashlib
root=Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\butterfly_552\analysis\extracted")
ct=(root/'encode.dat').read_bytes(); keyfile=(root/'encode.dat.key').read_bytes(); key=keyfile[:8]
N=len(ct); mask=(1<<64)-1

def enc8(p):
    assert len(p)==8
    a=bytes(p[i]^key[i] for i in range(8))
    b=bytes(a[i^1] for i in range(8))
    q=int.from_bytes(b,'little')
    q=((q<<1)|(q>>63))&mask
    r=q.to_bytes(8,'little')
    return bytes((r[i]+key[i])&255 for i in range(8))

def dec8(c):
    assert len(c)==8
    r=bytes((c[i]-key[i])&255 for i in range(8))
    b=bytes((r[i]>>1)|((r[(i+1)&7]&1)<<7) for i in range(8))
    a=bytes(b[i^1] for i in range(8))
    return bytes(a[i]^key[i] for i in range(8))

print('N=',N,'cipher_sha256=',hashlib.sha256(ct).hexdigest().upper())
print('main buffer allocation = N+8 =',N+8)
print('main writes length bytes at buffer[N:N+2] =',bytes([N&255,(N>>8)&255]).hex())
print('archive data bytes =',ct.hex())
body=bytearray()
for off in range(0,(N//8)*8,8):
    p=dec8(ct[off:off+8]); body.extend(p)
    out=enc8(p)
    print(f'complete block offset={off}: P={p.hex()} C={out.hex()} exact_match={out==ct[off:off+8]}')
print('complete decoded body bytes=',len(body),repr(bytes(body)))
print('complete decoded prefix=',bytes(body).decode('ascii'))
lastc=ct[32:36]
keyed=bytes((lastc[i]-key[i])&255 for i in range(4))
print('last ciphertext[32:36]=',lastc.hex(),'post-subtract=',keyed.hex())
# The two choices are all possible P2 values because the unavailable byte 36
# of ciphertext controls only the missing neighbor bit. P0/P1/P3 are fixed.
for p2 in (0x3a,0xba):
    tail=bytes([0xc3,0x38,p2,0xd7])
    for p6 in (0,0x80):
        work=bytearray(N+8)
        work[:32]=body
        work[32:36]=tail
        work[36]=N&255; work[37]=(N>>8)&255
        work[38]=p6; work[39]=0
        out=bytearray()
        # main processes block starts through floor((N-1)/8)*8 = 32 inclusive
        for off in range(0,((N-1)//8)*8+1,8):
            out.extend(enc8(work[off:off+8]))
        stored=bytes(out[:N])
        hit=stored==ct
        print(f'candidate tail={tail.hex()} hidden buffer[38:40]={work[38:40].hex()} full processed block={enc8(work[32:40]).hex()} emitted={stored[32:].hex()} exact_36_byte_match={hit}')
print('Conclusion: fully reproducible binary bodies contain non-text tail bytes; visible bytes do not distinguish P2 0x3a vs 0xba because differing bits map to unrecorded ciphertext byte 36.')
