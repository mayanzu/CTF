import struct, sys, re, pathlib
p = pathlib.Path(sys.argv[1])
b = p.read_bytes()
def u16(o): return struct.unpack_from('<H', b, o)[0]
def u32(o): return struct.unpack_from('<I', b, o)[0]
def u64(o): return struct.unpack_from('<Q', b, o)[0]
print(f'FILE={p}\nSIZE={len(b)} bytes\nMZ={b[:2]!r}')
if b[:2] != b'MZ': raise SystemExit('not PE')
pe = u32(0x3c); print(f'e_lfanew=0x{pe:x}; PE signature={b[pe:pe+4]!r}')
if b[pe:pe+4] != b'PE\0\0': raise SystemExit('bad PE signature')
coff=pe+4; machine=u16(coff); nsec=u16(coff+2); ts=u32(coff+4); sym=u32(coff+8); nsyms=u32(coff+12); osz=u16(coff+16); chars=u16(coff+18); opt=coff+20; magic=u16(opt)
print(f'MACHINE=0x{machine:04x}; sections={nsec}; timestamp=0x{ts:08x}; optional_size={osz}; characteristics=0x{chars:04x}; optional_magic=0x{magic:04x}')
if magic==0x10b: bits=32; imagebase=u32(opt+28); ddn=u32(opt+92); dd=opt+96
elif magic==0x20b: bits=64; imagebase=u64(opt+24); ddn=u32(opt+108); dd=opt+112
else: raise SystemExit('unknown optional header')
entry=u32(opt+16); section_align=u32(opt+32); file_align=u32(opt+36); size_image=u32(opt+56); size_headers=u32(opt+60); subsystem=u16(opt+68); dllchars=u16(opt+70)
print(f'BITS={bits}; entry_rva=0x{entry:x}; imagebase=0x{imagebase:x}; section_alignment=0x{section_align:x}; file_alignment=0x{file_align:x}; size_image=0x{size_image:x}; size_headers=0x{size_headers:x}; subsystem={subsystem}; dllchars=0x{dllchars:04x}; data_directories={ddn}')
sects=[]; sh=opt+osz
for i in range(nsec):
 o=sh+40*i; name=b[o:o+8].split(b'\0')[0].decode('ascii','replace'); vs,va,rs,rp=struct.unpack_from('<IIII',b,o+8); sc=u32(o+36); sects.append((name,va,vs,rp,rs,sc)); print(f'SECTION {name}: RVA=0x{va:x}, VirtualSize=0x{vs:x}, RawPtr=0x{rp:x}, RawSize=0x{rs:x}, Characteristics=0x{sc:08x}')
def rvaoff(r):
 if r < size_headers: return r
 for name,va,vs,rp,rs,sc in sects:
  if va <= r < va+max(vs,rs): return rp+(r-va)
 return None
dirs=[]
for i in range(min(ddn,16)):
 r,s=struct.unpack_from('<II',b,dd+8*i); dirs.append((r,s)); print(f'DIR[{i}] rva=0x{r:x} size=0x{s:x}')
# imports directory
if len(dirs)>1 and dirs[1][0]:
 print('--- IMPORTS ---'); off=rvaoff(dirs[1][0]); idx=0
 while off is not None and off+20<=len(b):
  oft,stamp,chain,namer,ft=struct.unpack_from('<IIIII',b,off)
  if not any((oft,stamp,chain,namer,ft)): break
  no=rvaoff(namer); dll=b[no:b.find(b'\0',no)].decode('ascii','replace') if no is not None else '<bad>'
  print(f'DLL {dll} FirstThunk=0x{ft:x} OFT=0x{oft:x}')
  thunk=oft or ft; to=rvaoff(thunk); step=8 if bits==64 else 4; ordinalmask=(1<<(bits-1))
  if to is not None:
   j=0
   while to+j*step+step<=len(b):
    val=int.from_bytes(b[to+j*step:to+j*step+step],'little')
    if val==0: break
    if val&ordinalmask: symn=f'ordinal#{val & (ordinalmask-1)}'
    else:
     hn=rvaoff(val & (ordinalmask-1)); symn=b[hn+2:b.find(b'\0',hn+2)].decode('ascii','replace') if hn is not None else f'rva_{val:x}'
    print('  '+symn); j+=1
  off+=20; idx+=1
# strings
print('--- ASCII STRINGS (>=4 chars) WITH OFFSETS ---')
for m in re.finditer(rb'[\x20-\x7e]{4,}',b):
 s=m.group().decode('ascii','replace')
 print(f'0x{m.start():04x}: {s[:500]}')
print('--- UTF16LE PRINTABLE STRINGS (>=4 chars) ---')
for start in (0,1):
 for m in re.finditer(rb'(?:[\x20-\x7e]\x00){4,}',b[start:]):
  off=start+m.start(); s=b[off:off+m.end()-m.start()].decode('utf-16le','replace')
  print(f'0x{off:04x}: {s[:300]}')
