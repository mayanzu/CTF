from pathlib import Path
from itertools import product
import hashlib
root=Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\butterfly_552\analysis\extracted")
ct=(root/"encode.dat").read_bytes(); keyfile=(root/"encode.dat.key").read_bytes(); key=keyfile[:8]
MASK=(1<<64)-1

def encrypt_block(p):
    # Independent direct formulation of the SSE/MMX sequence.
    v=bytes(p[i]^key[i] for i in range(8))
    swapped=bytes(v[i^1] for i in range(8))
    q=int.from_bytes(swapped,"little")
    rotated=((q<<1)|(q>>63))&MASK
    r=rotated.to_bytes(8,"little")
    return bytes((r[i]+key[i])&255 for i in range(8))

def decrypt_block(c):
    x=bytes((c[i]-key[i])&255 for i in range(8))
    # Inverse 64-bit rotate-left: byte i is X[i]>>1 plus bit0 of X[i+1].
    w=bytes((x[i]>>1)|((x[(i+1)&7]&1)<<7) for i in range(8))
    swapped=bytes(w[i^1] for i in range(8))
    return bytes(swapped[i]^key[i] for i in range(8))

print("ciphertext length",len(ct))
print("ciphertext sha256",hashlib.sha256(ct).hexdigest().upper())
print("key bytes",repr(key),key.hex())
plain=bytearray()
for off in range(0,32,8):
    block=ct[off:off+8]
    p=decrypt_block(block)
    check=encrypt_block(p)
    print(f"block@{off:02d}: ct={block.hex()} plain={p!r} reenc={check.hex()} match={check==block}")
    plain.extend(p)
print("recovered first 32",repr(bytes(plain)))
print("recovered first 32 hex",bytes(plain).hex())
last=ct[32:36]
print("last available ciphertext",last.hex())
keyed=bytes((last[i]-key[i])&255 for i in range(4))
print("last keyed bytes X[0:4]",keyed.hex())
# Inverse rotation and pair swap imply P[0]=W1^K0, P[1]=W0^K1,
# P[2]=W3^K2 depends on unknown X[4].lsb, P[3]=W2^K3.
for x4_lsb in (0,1):
    x=list(keyed)+[x4_lsb]+[0]*4
    w=[(x[i]>>1)|((x[i+1]&1)<<7) for i in range(8)]
    p=bytes(w[i^1]^key[i] for i in range(4))
    print(f"partial inverse with unknown X4.lsb={x4_lsb}: {p.hex()} {p!r}")
# Strict format check: first 32 bytes imply exactly 3 hex chars plus '}' remain
# for a 36-byte flag. Include the length footer main writes at offsets 36-37,
# with two zero allocator bytes as the requested concrete padding hypothesis.
hexchars=b"0123456789abcdefABCDEF"
hits=[]
for suffix3 in product(hexchars,repeat=3):
    p=bytes(suffix3)+b"}"
    full=p+bytes([len(ct)&255,(len(ct)>>8)&255,0,0])
    fwd=encrypt_block(full)
    if fwd[:4]==last:
        hits.append((p,fwd))
print("strict suffix hits (suffix=3 hex + brace; tail=24 00 00 00; compare all 4 available bytes):",len(hits))
for p,fwd in hits[:20]: print(repr(p),fwd.hex(),fwd[:4].hex())
example=b"000}"
example_block=example+bytes([len(ct)&255,(len(ct)>>8)&255,0,0])
print("example full 8-byte suffix block for 000}",example_block.hex())
print("example full ciphertext",encrypt_block(example_block).hex())
print("example written 4 bytes match",encrypt_block(example_block)[:4].hex(),last.hex(),encrypt_block(example_block)[:4]==last)
