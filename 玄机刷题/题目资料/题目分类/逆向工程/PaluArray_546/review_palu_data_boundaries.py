from pathlib import Path
import struct,hashlib
p=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\PaluArray_546\PaluArray_flag_unpacked.exe'); d=p.read_bytes()
pe=struct.unpack_from('<I',d,0x3c)[0]; opt=pe+24; base=struct.unpack_from('<Q',d,opt+24)[0]; n=struct.unpack_from('<H',d,pe+6)[0]; st=opt+struct.unpack_from('<H',d,pe+20)[0]
print('sha256',hashlib.sha256(d).hexdigest(),'imagebase',hex(base),'sections:')
for i in range(n):
 q=st+i*40; name=d[q:q+8].split(b'\0',1)[0].decode('ascii','replace'); vs,rv,rs,rp=struct.unpack_from('<IIII',d,q+8);print(name,'VA',hex(base+rv),'RVA',hex(rv),'raw size',hex(rs),'raw ptr',hex(rp),'virtual size',hex(vs))
for rva in [0x5e40,0x5e60,0x5e66,0x5e68,0x5e80,0x5e90,0x5ea0,0x9b48]:
 found=None
 for i in range(n):
  q=st+i*40; name=d[q:q+8].split(b'\0',1)[0].decode('ascii','replace');vs,rv,rs,rp=struct.unpack_from('<IIII',d,q+8)
  if rv<=rva<rv+rs:found=(name,rp+rva-rv);break
 if found:
  name,off=found; raw=d[off:off+96];
  print('\nRVA',hex(rva),'VA',hex(base+rva),'file',hex(off),'section',name)
  print('HEX',raw.hex())
  print('UTF16',repr(raw.decode('utf-16le','replace')))
  print('ASCII',repr(raw))
 else: print('RVA',hex(rva),'VA',hex(base+rva),'no raw file-backed section (possibly BSS)')
