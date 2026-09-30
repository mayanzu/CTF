"""Read-only decoder for Android binary XML manifest chunks."""
import struct
import sys
from pathlib import Path

b = Path(sys.argv[1]).read_bytes()
u16=lambda o: struct.unpack_from("<H", b, o)[0]
u32=lambda o: struct.unpack_from("<I", b, o)[0]
assert u16(0) == 0x0003, f"expected XML chunk, got 0x{u16(0):04x}"

def len8(pos):
    n=b[pos]; pos+=1
    if n & 0x80: n=((n&0x7f)<<8)|b[pos]; pos+=1
    return n,pos
def len16(pos):
    n=u16(pos); pos+=2
    if n & 0x8000: n=((n&0x7fff)<<16)|u16(pos); pos+=2
    return n,pos

strings=[]
ns_by_idx={}
chunks=[]
pos=8
while pos < len(b):
    typ,head,size=struct.unpack_from("<HHI",b,pos)
    chunks.append((typ,pos,head,size))
    if typ == 0x0001:
        count,styles,flags,string_start,style_start=struct.unpack_from("<IIIII",b,pos+8)
        offsets=[u32(pos+head+4*i) for i in range(count)]
        utf8=bool(flags & 0x100)
        for rel in offsets:
            q=pos+string_start+rel
            if utf8:
                _,q=len8(q); byte_count,q=len8(q)
                end=b.index(0,q); strings.append(b[q:end].decode("utf-8","replace"))
            else:
                char_count,q=len16(q); strings.append(b[q:q+2*char_count].decode("utf-16le","replace"))
    pos += size

def sx(idx): return "" if idx == 0xffffffff else strings[idx]
def value(dtype,data):
    if dtype == 0x03: return sx(data)
    if dtype == 0x01: return f"@0x{data:08x}"
    if dtype == 0x10: return str(data)
    if dtype == 0x11: return f"0x{data:x}"
    if dtype == 0x12: return str(bool(data))
    if dtype == 0x00: return "null"
    return f"typed(0x{dtype:02x},0x{data:08x})"

print(f"AndroidManifest.xml: {len(b)} bytes, {len(chunks)} chunks")
for typ,off,head,size in chunks:
    if typ == 0x0100:
        prefix,uri=struct.unpack_from("<II",b,off+16)
        ns_by_idx[uri]=sx(prefix)
    elif typ == 0x0102:
        line=u32(off+8); name_idx=u32(off+20)
        attr_start,attr_size,attr_count=struct.unpack_from("<HHH",b,off+24)
        attrs=[]
        base=off+16+attr_start
        for i in range(attr_count):
            a=base+i*attr_size
            ns,name,raw=struct.unpack_from("<III",b,a)
            vsize,res0,dtype=struct.unpack_from("<HBB",b,a+12)
            data=u32(a+16)
            attr_name=sx(name)
            uri=sx(ns)
            prefix=next((p for u,p in ns_by_idx.items() if u==uri),"") if uri else ""
            label=(prefix+":" if prefix else "")+attr_name
            val=sx(raw) if raw != 0xffffffff else value(dtype,data)
            attrs.append(f"{label}={val!r}")
        print(f"START <{sx(name_idx)}> line={line}: " + ", ".join(attrs))
    elif typ == 0x0103:
        print(f"END </{sx(u32(off+20))}>")
