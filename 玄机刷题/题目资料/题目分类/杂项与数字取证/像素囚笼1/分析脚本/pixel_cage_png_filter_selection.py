from pathlib import Path
from PIL import Image
import zlib,collections
p=Path(r'D:\Downloads\像素囚笼附件 (1)\challenge.png'); b=p.read_bytes()
assert b[:8]==b'\x89PNG\r\n\x1a\n'
pos=8; idat=bytearray(); info=None
while pos<len(b):
 n=int.from_bytes(b[pos:pos+4],'big'); typ=b[pos+4:pos+8]; data=b[pos+8:pos+8+n]
 if typ==b'IHDR': info=(int.from_bytes(data[:4],'big'),int.from_bytes(data[4:8],'big'),data[8],data[9])
 if typ==b'IDAT':idat.extend(data)
 pos+=12+n
 if typ==b'IEND':break
w,h,depth,ctype=info; assert (depth,ctype)==(8,2)
bpp=3; stride=w*bpp; raw=zlib.decompress(idat)
assert len(raw)==h*(stride+1)
a=Image.open(p).convert('RGB').tobytes()
actual=[]; costs=[]; mismatches=[]; chosen=[]
def paeth(a,b,c):
 q=a+b-c; pa=abs(q-a);pb=abs(q-b);pc=abs(q-c)
 return a if pa<=pb and pa<=pc else b if pb<=pc else c
prev=bytes(stride)
for y in range(h):
 base=y*(stride+1); ft=raw[base]; filt=raw[base+1:base+1+stride]; cur=a[y*stride:(y+1)*stride]
 actual.append(ft); rowcost=[]
 for f in range(5):
  residue=bytearray(stride)
  for i,x in enumerate(cur):
   left=cur[i-bpp] if i>=bpp else 0; up=prev[i]; upperleft=prev[i-bpp] if i>=bpp else 0
   pred=(0 if f==0 else left if f==1 else up if f==2 else (left+up)//2 if f==3 else paeth(left,up,upperleft))
   residue[i]=(x-pred)&255
  # PNG adaptive encoders commonly score signed residual magnitude.
  score=sum(abs(v if v<128 else v-256) for v in residue)
  rowcost.append(score)
  if f==ft and bytes(residue)!=filt:
   mismatches.append((y,f,i))
 costs.append(rowcost)
 best=min(rowcost); chosen.append([i for i,v in enumerate(rowcost) if v==best])
 prev=cur
nonminimum=[(y,actual[y],costs[y],chosen[y]) for y in range(h) if actual[y] not in chosen[y]]
print('dimensions:',w,h,'bpp:',bpp,'filter counts:',dict(collections.Counter(actual)))
print('rows where actual filter bytes do not reconstruct original pixels:',len(mismatches))
print('rows where actual filter is not minimum signed-residual score:',len(nonminimum))
print('actual filter vs minimum-score choice:',collections.Counter((actual[y],tuple(chosen[y])) for y in range(h)))
print('first non-minimum rows (row,actual,costs[0..4],minimum):',nonminimum[:40])
print('sum costs by filter:',[sum(row[f] for row in costs) for f in range(5)])
