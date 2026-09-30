import sys, struct, re, hashlib
from pathlib import Path
p=Path(sys.argv[1]); b=p.read_bytes()
print(f"file={p} size={len(b)} sha256={hashlib.sha256(b).hexdigest()}")
print(f"DOS_magic={b[:2]!r} e_lfanew=0x{struct.unpack_from('<I',b,0x3c)[0]:x}")
o=struct.unpack_from('<I',b,0x3c)[0]
print(f"PE_signature={b[o:o+4]!r}")
machine,nsec,timestamp,ptrsym,nsym,opt_size,chars=struct.unpack_from('<HHIIIHH',b,o+4)
print(f"machine=0x{machine:04x} sections={nsec} timestamp=0x{timestamp:08x} optional_size={opt_size} characteristics=0x{chars:04x}")
opt=o+24; magic=struct.unpack_from('<H',b,opt)[0]
print(f"optional_magic=0x{magic:04x}")
if magic==0x10b: imagebase=struct.unpack_from('<I',b,opt+28)[0]; dd=opt+96
elif magic==0x20b: imagebase=struct.unpack_from('<Q',b,opt+24)[0]; dd=opt+112
else: imagebase=None; dd=None
if imagebase is not None:
    print(f"imagebase=0x{imagebase:x} entry_rva=0x{struct.unpack_from('<I',b,opt+16)[0]:x} image_size=0x{struct.unpack_from('<I',b,opt+56)[0]:x} subsystem={struct.unpack_from('<H',b,opt+68)[0]}")
secs=[]; sh=opt+opt_size
for i in range(nsec):
    x=sh+i*40; name=b[x:x+8].split(b'\0')[0].decode('ascii','replace')
    vs,va,rs,rp=struct.unpack_from('<IIII',b,x+8)
    sc=struct.unpack_from('<I',b,x+36)[0]
    secs.append((name,va,max(vs,rs),rp,rs))
    print(f"section[{i}] name={name!r} rva=0x{va:x} vsize=0x{vs:x} raw=0x{rp:x}+0x{rs:x} flags=0x{sc:08x}")
def rvaoff(r):
    for name,va,span,rp,rs in secs:
        if va<=r<va+span:
            z=r-va
            if z<rs:return rp+z
    return None
if dd is not None:
    imp_rva,imp_sz=struct.unpack_from('<II',b,dd+8)
    print(f"import_dir_rva=0x{imp_rva:x} size=0x{imp_sz:x}")
    io=rvaoff(imp_rva) if imp_rva else None
    if io is not None:
        for n in range(128):
            d=b[io+n*20:io+(n+1)*20]
            if len(d)<20:break
            ilt,stamp,forwarder,name_rva,ft=struct.unpack('<IIIII',d)
            if not (ilt|name_rva|ft):break
            no=rvaoff(name_rva)
            nm=b[no:b.find(b'\0',no)].decode('ascii','replace') if no is not None else '?'
            print(f"import_dll={nm}")
# ASCII strings
strings=[]
for m in re.finditer(rb'[\x20-\x7e]{4,}',b): strings.append((m.start(),m.group().decode('ascii','replace')))
print('--- ASCII STRINGS (>=4) ---')
for off,s in strings: print(f"0x{off:06x}: {s}")
print('--- UTF16LE STRINGS (>=4) ---')
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){4,}',b):
    try:s=m.group().decode('utf-16le')
    except:continue
    print(f"0x{m.start():06x}: {s}")

