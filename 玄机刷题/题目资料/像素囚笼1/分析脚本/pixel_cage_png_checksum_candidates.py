from pathlib import Path
from zipfile import ZipFile
import zlib,hashlib,base64,struct,itertools
p=Path(r'D:\Downloads\像素囚笼附件 (1)\challenge.png'); raw=p.read_bytes()
chunks=[];pos=8;idat=bytearray()
while pos<len(raw):
 n=int.from_bytes(raw[pos:pos+4],'big'); typ=raw[pos+4:pos+8]; data=raw[pos+8:pos+8+n]; crc=int.from_bytes(raw[pos+8+n:pos+12+n],'big')
 chunks.append((typ,data,crc));
 if typ==b'IDAT':idat.extend(data)
 pos+=12+n
 if typ==b'IEND':break
# Extract independent values that can plausibly serve as a format-derived password.
vals=[len(raw),len(idat),zlib.crc32(raw),zlib.crc32(idat),zlib.adler32(zlib.decompress(idat))]
for typ,data,crc in chunks:
 vals.extend([len(data),crc,zlib.crc32(typ+data),zlib.adler32(data)])
for label,v in zip(['png_length','idat_length','png_crc','idat_crc','pixel_adler']+sum(([t.decode()+'_len',t.decode()+'_crc',t.decode()+'_crc_calc',t.decode()+'_adler'] for t,d,c in chunks),[]),vals):
 print(label, v, hex(v))
candidates=set()
for n in vals:
 forms={str(n),f'{n:08d}',f'{n:08x}',f'{n:08X}',hex(n)[2:],hex(n)[2:].upper(),str(n)[::-1],hex(n)[2:][::-1]}
 for s in forms:
  for v in (s,s.lower(),s.upper()):
   candidates.add(v.encode())
   candidates.add(b'0x'+v.encode())
   candidates.add(b'#'+v.encode())
 for width in (1,2,4):
  if n < 1<<(8*width):
   bb=n.to_bytes(width,'big'); candidates.update([bb,bb[::-1],bb.hex().encode(),bb.hex().upper().encode(),base64.b64encode(bb)])
for (a,b) in itertools.product(vals,repeat=2):
 for sep in ('','_','-','.',':'):
  candidates.add((str(a)+sep+str(b)).encode()); candidates.add((f'{a:08x}'+sep+f'{b:08x}').encode())
for order in itertools.permutations([c[2] for c in chunks]):
 for sep in ('','-', '_',','):
  s=sep.join(f'{n:08x}' for n in order); candidates.add(s.encode())
print('checksum-derived candidate count:',len(candidates))
with ZipFile(p) as z:
 for pwd in candidates:
  try:
   data=z.read('secret.txt',pwd=pwd)
   print('PASSWORD FOUND:',repr(pwd)); print('SECRET.TXT:',data.decode(errors='replace'));break
  except Exception:pass
 else:print('No PNG chunk CRC/Adler/length representation matched.')
