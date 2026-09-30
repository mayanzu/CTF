import re, struct, pathlib, sys
p=pathlib.Path(sys.argv[1]); b=p.read_bytes()
u16=lambda o: struct.unpack_from('<H',b,o)[0]
u32=lambda o: struct.unpack_from('<I',b,o)[0]
u64=lambda o: struct.unpack_from('<Q',b,o)[0]
pe=u32(0x3c); print(f'file={p} size={len(b)} DOS.e_lfanew=0x{pe:x}')
print('PE signature=',b[pe:pe+4], 'machine=0x%04x'%u16(pe+4),'sections=',u16(pe+6),'timestamp=0x%08x'%u32(pe+8),'optional_size=',u16(pe+20))
o=pe+24; magic=u16(o); print('optional_magic=0x%04x'%magic)
if magic==0x20b: ep=u32(o+16); ib=u64(o+24); dd=o+112
else: ep=u32(o+16); ib=u32(o+28); dd=o+96
print('entry_rva=0x%x'%ep,'image_base=0x%x'%ib,'entry_va=0x%x'%(ib+ep))
nd=u32(o+(108 if magic==0x20b else 92)); print('data_directories=',nd)
for n in range(min(nd,16)):
 rva,size=struct.unpack_from('<II',b,dd+8*n)
 if rva or size: print(f'dir[{n}] rva=0x{rva:x} size=0x{size:x}')
sh=o+u16(pe+20); secs=[]
for i in range(u16(pe+6)):
 s=sh+40*i; name=b[s:s+8].split(b'\0')[0].decode('ascii','replace'); vs,va,rs,rp=struct.unpack_from('<IIII',b,s+8); ch=u32(s+36); secs.append((name,va,vs,rp,rs,ch)); print(f'section {name!r} va=0x{va:x} vsize=0x{vs:x} raw=0x{rp:x}+0x{rs:x} flags=0x{ch:x}')
def rvaoff(r):
 for name,va,vs,rp,rs,ch in secs:
  if va<=r<va+max(vs,rs): return rp+(r-va)
 raise ValueError(hex(r))
# strings, with raw offsets
pat=re.compile(rb'[\x20-\x7e]{4,}')
strs=[(m.start(),m.group().decode('ascii','replace')) for m in pat.finditer(b)]
print('printable_strings=',len(strs))
for off,s in strs:
 if re.search(r'Input Secret|Passed|Invalid|base58|rsa|RSA|crypto|flag|main\\.|encrypt|decrypt|asymmetric|key|secret',s,re.I):
  print(f'STR 0x{off:x}: {s[:500]}')
# Find embedded Go build info and pclntab versions.
for sig,label in [(b'\xff Go buildinf:','go_buildinfo'),(b'\xfa\xff\xff\xff','pclntab_magic_le?'),(b'\xf1\xff\xff\xff','pclntab_magic_le?')]:
 start=0
 while True:
  i=b.find(sig,start)
  if i<0: break
  print(f'{label} at raw 0x{i:x}: {b[i:i+80].hex()}'); start=i+1
