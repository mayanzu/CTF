"""End-to-end static forward closure for Xuanji #543.

Reconstructs constants from the disassembly, derives the first key/table/flag,
and verifies every transform in the forward direction. Does not launch the PE.
"""
from __future__ import annotations
import pathlib, re

ROOT = pathlib.Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\Base_543")
DISASM = ROOT / "analysis" / "objdump_disassembly_intel_ascii.txt"
OUT = ROOT / "records" / "543_final_verification.txt"
text = DISASM.read_text(encoding="utf-8")
MASK = 0xffffffff
DELTA = 0x9e3779b9
tea_key = [0x12345678, 0x3456789a, 0x89abcdef, 0x12345678]
cipher_words = (0xa92f3865, 0x9e60e953)

def mix(y,s,a,b):
    return (((((y << 4) & MASK) + a) & MASK) ^ ((y+s)&MASK) ^ (((y>>5)+b)&MASK))

def block_encrypt(v0,v1):
    total=0
    for _ in range(32):
        total=(total+DELTA)&MASK
        v0=(v0+mix(v1,total,tea_key[0],tea_key[1]))&MASK
        v1=(v1+mix(v0,total,tea_key[2],tea_key[3]))&MASK
    return v0,v1

# Invert the straight-line 32-round check and assert the forward result.
v0,v1=cipher_words
total=(DELTA*32)&MASK
while total:
    v1=(v1-mix(v0,total,tea_key[2],tea_key[3]))&MASK
    v0=(v0-mix(v1,total,tea_key[0],tea_key[1]))&MASK
    total=(total-DELTA)&MASK
key_bytes=v0.to_bytes(4,"little")+v1.to_bytes(4,"little")
assert block_encrypt(v0,v1)==cipher_words

# Extract 64 table target bytes and the embedded Base32 text from main's
# explicit BYTE writes (rbp+0x220..0x25f, rbp+0x2d8..0x307).
writes={}
for line in text.splitlines():
    m=re.search(r"mov\s+BYTE PTR /[rbp\+0x([0-9a-f]+)/],0x([0-9a-f]+)",line,re.I)
    if m:
        writes[int(m.group(1),16)]=int(m.group(2),16)
encrypted_table=bytes(writes[x] for x in range(0x220,0x260))
encoded=bytes(writes[x] for x in range(0x2d8,0x308))
assert len(encrypted_table)==64 and len(encoded)==48

# Exact static KSA + additive PRGA translated from functions at 0x140011d10
# and 0x140011ea0.
S=list(range(256)); j=0
for i in range(256):
    j=(j+S[i]+key_bytes[i%len(key_bytes)])&0xff
    S[i],S[j]=S[j],S[i]
i=j=0; ks=[]
for _ in range(64):
    i=(i+1)&0xff
    j=(j+S[i])&0xff
    S[i],S[j]=S[j],S[i]
    ks.append(S[(S[i]+S[j])&0xff])
keystream=bytes(ks)
table=bytes((c-k)&0xff for c,k in zip(encrypted_table,keystream))
assert bytes((c+k)&0xff for c,k in zip(table,keystream))==encrypted_table
alphabet=table[1:33]
assert len(alphabet)==32 and len(set(alphabet))==32
assert all(0x20<=c<=0x7e for c in table)

# Invert the 5-byte -> 8 symbols encoder using the alphabet table[1:33].
index={c:i for i,c in enumerate(alphabet)}
assert all(c in index for c in encoded)
bitstream="".join(f"{index[c]:05b}" for c in encoded)
decoded=bytes(int(bitstream[k:k+8],2) for k in range(0,len(bitstream),8))
flag=decoded.decode("ascii")
assert len(decoded)==30
assert flag.startswith("flag{") and flag.endswith("}")
assert decoded[-1:]==b"}"

def encode_base32_chunks(data: bytes) -> bytes:
    out=bytearray()
    for off in range(0,len(data),5):
        chunk=data[off:off+5]
        value=0
        shifts=(32,24,16,8,0)
        for c,shift in zip(chunk,shifts):
            value |= c<<shift
        for shift in (35,30,25,20,15,10,5,0):
            out.append(alphabet[(value>>shift)&0x1f])
    return bytes(out)

forward_full=encode_base32_chunks(decoded)
forward_truncated=encode_base32_chunks(decoded[:-1])
assert forward_full==encoded
# The binary's comparator loop at 0x140012435 uses i<0x1e (30), so a 29-byte
# scanf-limited input still matches the compared prefix; this is a local bug.
assert forward_truncated[:30]==encoded[:30]
assert len(decoded)==30 and len(decoded[:-1])==29

lines=[
    "Challenge #543 static end-to-end closure; executable never launched.",
    f"First-level key bytes: {key_bytes!r}",
    f"First-level key ASCII: {key_bytes.decode('ascii')}",
    f"Forward 32-round block result: {[hex(x) for x in block_encrypt(v0,v1)]}",
    f"Expected target words: {[hex(x) for x in cipher_words]}",
    "First-level exact match: True",
    f"Embedded 64-byte second-stage target: {encrypted_table.hex()}",
    f"RC4/additive keystream: {keystream.hex()}",
    f"Recovered 64-byte Base_Table: {table.decode('ascii')}",
    f"Base_Table length / printable / unique: {len(table)} / {all(0x20<=c<=0x7e for c in table)} / {len(set(table))}",
    f"Alphabet selected by assembly (table[1:33]): {alphabet.decode('ascii')}",
    f"Alphabet length and uniqueness: {len(alphabet)} / {len(set(alphabet))}",
    f"Additive RC4 forward output: {bytes((c+k)&0xff for c,k in zip(table,keystream)).hex()}",
    "64-byte forward match: True",
    f"Embedded Base32-like target ({len(encoded)} bytes): {encoded.decode('ascii')}",
    f"Decoded exact 30-byte candidate: {flag}",
    f"Full candidate Base32 forward output: {forward_full.decode('ascii')}",
    f"Full 48-byte match: {forward_full==encoded}",
    f"29-byte prefix (for local scanf cap): {flag[:-1]}",
    f"29-byte prefix forward output begins: {forward_truncated[:30].decode('ascii')}",
    f"Comparator range from disassembly: 30 bytes (i=0..29)",
    f"Prefix matches locally compared target: {forward_truncated[:30]==encoded[:30]}",
    "Caveat: scanf format is %29s (max 29 ASCII bytes); the complete platform candidate is recovered from the embedded 48-byte target and is 30 bytes. The static comparator only checks first 30 encoded bytes, which makes the local interactive check weaker than the embedded full target.",
]
OUT.write_text("\n".join(lines)+"\n",encoding="utf-8")
print("\n".join(lines))
print("verification_file="+str(OUT))

