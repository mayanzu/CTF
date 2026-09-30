from pathlib import Path
import struct,hashlib,sys
sys.stdout.reconfigure(encoding='utf-8',errors='backslashreplace')
p=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\PaluArray_546\PaluArray_flag_unpacked.exe');d=p.read_bytes()
pe=struct.unpack_from('<I',d,0x3c)[0];opt=pe+24;base=struct.unpack_from('<Q',d,opt+24)[0];n=struct.unpack_from('<H',d,pe+6)[0];st=opt+struct.unpack_from('<H',d,pe+20)[0];ss=[]
for j in range(n):
 q=st+j*40;nm=d[q:q+8].split(b'\0',1)[0].decode('ascii','replace');vs,rv,rs,rp=struct.unpack_from('<IIII',d,q+8);ss.append((nm,vs,rv,rs,rp))
def fo(r):
 for nm,vs,rv,rs,rp in ss:
  if rv<=r<rv+rs:return rp+r-rv
 return None
def dump_rva(a,b):
 f=fo(a);print(f'RVA {a:#x}..{b:#x} fileoff {f}');
 if f is not None:
  for i in range(a,b,16):
   q=fo(i);row=d[q:q+min(16,b-i)];print(f'{i:06x}: {row.hex(" ")} | {row!r}')
print('SHA256',hashlib.sha256(d).hexdigest())
print('SECTIONS',[(x[0],hex(x[1]),hex(x[2]),hex(x[3]),hex(x[4])) for x in ss])
dump_rva(0x5e40,0x5ea8)
dump_rva(0x9b20,0x9b80)
for r in [0x5e66,0x5e68,0x5e6a,0x9b48]:
 f=fo(r);print('RVA',hex(r),'fileoffset',f)
 if f is not None:
  print('  qwords',[(hex(i),hex(struct.unpack_from('<Q',d,fo(r)+i)[0])) for i in range(0, min(0x30,len(d)-fo(r)-8),8)])
  for offset in range(0,0x30,2):
   try: ch=d[fo(r)+offset:fo(r)+offset+2].decode('utf-16le')
   except: ch='?'
   if ch=='\0':break
   print('  UTF16+',hex(offset),repr(ch))
