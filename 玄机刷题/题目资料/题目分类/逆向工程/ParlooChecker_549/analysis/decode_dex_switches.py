#!/usr/bin/env python3
"""Decode DEX sparse/packed switch payloads and Java hashes for app classes."""
import hashlib
import struct
import sys
from pathlib import Path

p = Path(sys.argv[1]); b = p.read_bytes()
u16 = lambda o: struct.unpack_from('<H', b, o)[0]
u32 = lambda o: struct.unpack_from('<I', b, o)[0]
s32 = lambda x: x - 0x100000000 if x & 0x80000000 else x
def uleb(off):
    v = shift = 0
    while True:
        c = b[off]; off += 1; v |= (c & 127) << shift
        if c < 128: return v, off
        shift += 7
def readstr(off):
    _, off = uleb(off); end = b.index(0, off)
    return b[off:end].replace(b'\xc0\x80', b'\x00').decode('utf-8', 'replace')
sc, so = u32(0x38), u32(0x3c)
tc, to = u32(0x40), u32(0x44)
pcnt, po = u32(0x48), u32(0x4c)
mc, mo = u32(0x58), u32(0x5c)
cc, co = u32(0x60), u32(0x64)
strings = [readstr(u32(so+4*i)) for i in range(sc)]
types = [strings[u32(to+4*i)] for i in range(tc)]
protos = []
for i in range(pcnt):
    _shorty, ret, params = struct.unpack_from('<III', b, po+12*i)
    args = []
    if params:
        n = u32(params); args = [types[u16(params+4+2*j)] for j in range(n)]
    protos.append('(' + ''.join(args) + ')' + types[ret])
methods=[]
for i in range(mc):
    ci, pi, ni = struct.unpack_from('<HHI', b, mo+8*i)
    methods.append((types[ci], strings[ni], protos[pi]))
def class_methods(off):
    sf, off = uleb(off); inf, off = uleb(off); dm, off = uleb(off); vm, off = uleb(off)
    for n in (sf, inf):
        idx=0
        for _ in range(n):
            diff, off = uleb(off); idx += diff
            _access, off = uleb(off)
    for kind,n in (('direct',dm),('virtual',vm)):
        idx=0
        for _ in range(n):
            diff,off=uleb(off);idx+=diff
            access,off=uleb(off);code,off=uleb(off)
            yield kind,idx,access,code
def jhash(s):
    h=0
    raw=s.encode('utf-16le')
    for i in range(0,len(raw),2): h=(31*h+int.from_bytes(raw[i:i+2],'little'))&0xffffffff
    return s32(h)
WIDTH=[1]*256
for op in (0x02,0x05,0x08,0x13,0x15,0x16,0x19,0x1a,0x1c,0x1f,0x20,0x22,0x23,0x29,*range(0x32,0x6e),*range(0xd0,0xe3),0xfe,0xff): WIDTH[op]=2
for op in (0x03,0x06,0x09,0x14,0x17,0x1b,0x24,0x25,0x26,0x2a,0x2b,0x2c,*range(0x6e,0x73),*range(0x74,0x79),0xfa,0xfc,0xfd): WIDTH[op]=3
WIDTH[0x18]=5;WIDTH[0xfb]=4
print(f"DEX={p} size={len(b)} sha256={hashlib.sha256(b).hexdigest().upper()}")
print('--- Java String.hashCode for app ciphertext strings ---')
for i,s in enumerate(strings):
    if len(s)>80: print(f'STRING[{i}] len={len(s)} java_hash={jhash(s):d} hex={jhash(s)&0xffffffff:08x}')
print('--- switch maps by app method ---')
for ci in range(cc):
    class_idx, access, sup, inter, src, ann, cd, sv = struct.unpack_from('<8I',b,co+32*ci)
    desc=types[class_idx]
    if 'Lcom/linkhash/parloochecker/' not in desc or not cd: continue
    for kind,mi,flags,code in class_methods(cd):
        if not code: continue
        n=u32(code+12); words=list(struct.unpack_from('<'+'H'*n,b,code+16)); pc=0
        print(f"METHOD {methods[mi]} code=0x{code:x} units={n}")
        while pc<n:
            w=words[pc];op=w&255;width=WIDTH[op]
            if op==0x18:width=5
            if op==0 and (w>>8) in (1,2,3):
                ident=w>>8
                if ident==1: width=4+2*words[pc+1]
                elif ident==2: width=2+4*words[pc+1]
                else: width=4+(words[pc+1]*(words[pc+2]|words[pc+3]<<16)+1)//2
            if op in (0x2b,0x2c):
                off=s32(words[pc+1]|words[pc+2]<<16)
                pl=pc+off; ident=words[pl]
                size=words[pl+1]
                if op==0x2c:
                    keys=[s32(words[pl+2+2*i]|words[pl+3+2*i]<<16) for i in range(size)]
                    tbase=pl+2+2*size
                    dest=[pc+s32(words[tbase+2*i]|words[tbase+2*i+1]<<16) for i in range(size)]
                    pairs=list(zip(keys,dest))
                else:
                    first=s32(words[pl+2]|words[pl+3]<<16)
                    pairs=[(first+i, pc+s32(words[pl+4+2*i]|words[pl+5+2*i]<<16)) for i in range(size)]
                print(f'  SWITCH pc=0x{pc:04x} opcode={op:02x} payload=0x{pl:04x} cases={pairs}')
            pc += max(1,width)
