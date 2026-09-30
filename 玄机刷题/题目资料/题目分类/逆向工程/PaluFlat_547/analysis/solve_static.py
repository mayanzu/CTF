from pathlib import Path
import struct

ROOT=Path(__file__).resolve().parent.parent
FULL=ROOT/"analysis"/"extracted"/"PaluFlat.exe"
HEAD=ROOT/"analysis"/"PaluFlat_head_0x5000.bin"
IMAGE=HEAD.read_bytes()
with FULL.open("rb") as f:
    full_size=FULL.stat().st_size
    assert f.read(len(IMAGE))==IMAGE, "bounded analysis copy differs from source prefix"
assert full_size==1<<30

peoff=struct.unpack_from("<I",IMAGE,0x3c)[0]
assert IMAGE[peoff:peoff+4]==b"PE\0\0"
machine,nsects,_,_,_,optsz,_=struct.unpack_from("<HHIIIHH",IMAGE,peoff+4)
opt=peoff+24
assert machine==0x8664
assert struct.unpack_from("<H",IMAGE,opt)[0]==0x20b
imagebase=struct.unpack_from("<Q",IMAGE,opt+24)[0]
sections=[]
for i in range(nsects):
    p=opt+optsz+i*40
    raw=IMAGE[p:p+40]
    name=raw[:8].split(b"\0",1)[0].decode("ascii")
    vsize,rva,rsize,rptr=struct.unpack_from("<IIII",raw,8)
    sections.append((name,rva,vsize,rptr,rsize))
def fileoff(va):
    rva=va-imagebase
    for name,srva,vsize,rptr,rsize in sections:
        if srva<=rva<srva+max(vsize,rsize):
            return rptr+(rva-srva)
    raise ValueError(f"unmapped VA {va:#x}")

# main's 19 mov byte [rbp+disp8], imm8 instructions begin at VA 0x4020b4.
target=[]
start=fileoff(0x4020b4)
for i in range(19):
    ins=IMAGE[start+4*i:start+4*i+4]
    assert ins[:2]==b"\xc6\x45" and ins[2]==0xa0+i, (i,ins.hex())
    target.append(ins[3])
target=bytes(target)
# The following instruction sets the required length to 0x13 (19).
lenins=IMAGE[fileoff(0x402100):fileoff(0x402100)+10]
assert lenins[:2]==b"\xc7\x85"
assert struct.unpack_from("<I",lenins,6)[0]==19

# Strings are immediate byte arrays in the transform routine: "palu" and "flat".
palu=IMAGE[fileoff(0x401560)+3:fileoff(0x401560)+7]
flat=IMAGE[fileoff(0x40156b)+3:fileoff(0x40156b)+7]
assert palu==b"palu" and flat==b"flat"
seedins=IMAGE[fileoff(0x4015ae):fileoff(0x4015ae)+7]
assert seedins[:3]==b"\xc7\x45\xd8"
seed=struct.unpack_from("<I",seedins,3)[0]
assert seed==0x3039

# Static branch trace for this constant: 0 -> 10 -> 12 -> 2 -> 3 -> 4 -> 0.
# Bits: b0=1,b2=0,b13=1,b14=0,b6=b7=b8=0,b9=1,b15=0.
assert ((seed>>0)&1, (seed>>2)&1, (seed>>13)&1, (seed>>14)&1)==(1,0,1,0)
assert [((seed>>b)&1) for b in (6,7,8,9,10,11)]==[0,0,0,0,0,0]
def key_at(i):
    # The dispatch blocks choose palu on even i and flat on odd i; both are length 4.
    return (palu if i%2==0 else flat)[i%4]
def decode_byte(c,k):
    x=(~c)&0xff
    x=(x+0x55)&0xff
    x=((x<<4)|(x>>4))&0xff       # nibble swap is its own inverse
    return x^k
def encode_byte(p,k):
    x=p^k
    x=((x<<4)|(x>>4))&0xff
    x=(x-0x55)&0xff
    return (~x)&0xff
plain=bytes(decode_byte(c,key_at(i)) for i,c in enumerate(target))
forward=bytes(encode_byte(p,key_at(i)) for i,p in enumerate(plain))
print("full PE size:",full_size)
print("PE header-copy size:",len(IMAGE))
print("ImageBase:",hex(imagebase))
print("target VA / file offset:",hex(0x4020b4),hex(start))
print("embedded length:",len(target))
print("key strings:",palu,flat,"seed:",hex(seed))
print("key bytes:",bytes(key_at(i) for i in range(len(target))).hex())
print("target ciphertext:",target.hex())
print("candidate hex:",plain.hex())
print("candidate:",plain.decode("ascii"))
print("candidate length:",len(plain))
print("forward result:",forward.hex())
print("forward matches all bytes:",forward==target)
print("NUL target positions:",[i for i,b in enumerate(target) if b==0])
assert len(plain)==19 and plain.startswith(b"flag{") and plain.endswith(b"}")
assert forward==target
