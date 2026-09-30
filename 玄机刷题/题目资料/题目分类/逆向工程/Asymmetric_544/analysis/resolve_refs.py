import pathlib,struct,sys
b=pathlib.Path(sys.argv[1]).read_bytes(); u32=lambda o:struct.unpack_from('<I',b,o)[0]; i32=lambda o:struct.unpack_from('<i',b,o)[0]; u64=lambda o:struct.unpack_from('<Q',b,o)[0]
h=b.find(b'\xf1\xff\xff\xff\x00\x00\x01\x08');n=u64(h+8);text=u64(h+24);names=h+u64(h+32);base=h+u64(h+64);fs=[]
for i in range(n):
 ent=u32(base+8*i); fo=u32(base+8*i+4); no=i32(base+fo+4); nm=b[names+no:].split(b'\0',1)[0].decode('utf8','replace');fs.append((text+ent,nm))
secs=[]; pe=u32(0x3c);o=pe+24; magic=u32(o)&0xffff; sh=o+(u16:=struct.unpack_from('<H',b,pe+20)[0])
for i in range(struct.unpack_from('<H',b,pe+6)[0]):
 s=sh+40*i;name=b[s:s+8].split(b'\0')[0].decode();vs,va,rs,rp=struct.unpack_from('<IIII',b,s+8);secs.append((name,va,max(vs,rs),rp,rs))
def offva(va):
 for name,va0,span,rp,rs in secs:
  if va0<=va-0x400000<va0+span:return rp+(va-0x400000-va0),name
 return None,None
calls=[0x48aac0,0x4663b0,0x44b840,0x46671a,0x470340,0x46fae0,0x495400,0x49edc0,0x495580,0x49fc80,0x44f960,0x403160,0x48aba0,0x463e20]
print('=== Called function target mapping ===')
for t in calls:
 i=max((i for i,x in enumerate(fs) if x[0]<=t),default=-1); print(f'0x{t:x}: {fs[i][1] if i>=0 else "?"} starts=0x{fs[i][0]:x}' if i>=0 else f'0x{t:x}: ?')
refs=[0x4adca0,0x4eb610,0x4ebc42,0x4add24,0x4ebc1e,0x4adea6,0x4eb624,0x4ebc38,0x4cb6a0,0x5e88c0,0x4cb405,0x4ae660]
print('=== Referenced static data ===')
for va in refs:
 off,sec=offva(va)
 if off is None:print(f'VA 0x{va:x} unmapped');continue
 x=b[off:off+128];print(f'VA=0x{va:x} raw=0x{off:x} sec={sec} hex={x[:64].hex()} ascii={x[:128]!r}')
