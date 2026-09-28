from pathlib import Path
from PIL import Image
import zlib,collections
p=Path(r'D:\Downloads\像素囚笼附件 (1)\challenge.png'); b=p.read_bytes();pos=8;idat=bytearray();ihdr=None
while pos<len(b):
 n=int.from_bytes(b[pos:pos+4],'big');t=b[pos+4:pos+8];d=b[pos+8:pos+8+n]
 if t==b'IHDR':ihdr=(int.from_bytes(d[:4],'big'),int.from_bytes(d[4:8],'big'),d[8],d[9])
 if t==b'IDAT':idat.extend(d)
 pos+=12+n
 if t==b'IEND':break
w,h,depth,ctype=ihdr;raw=zlib.decompress(idat);a=Image.open(p).convert('RGB').tobytes();bpp=3;stride=w*bpp;prev=bytes(stride); ties=[]
def paeth(x,y,z):
 q=x+y-z;v=[abs(q-x),abs(q-y),abs(q-z)];return [x,y,z][v.index(min(v))]
for y in range(h):
 off=y*(stride+1);actual=raw[off];filt=raw[off+1:off+1+stride];cur=a[y*stride:(y+1)*stride];scores=[]
 for f in range(5):
  vals=[]
  for i,x in enumerate(cur):
   left=cur[i-3] if i>=3 else 0;up=prev[i];ul=prev[i-3] if i>=3 else 0
   pred=(0 if f==0 else left if f==1 else up if f==2 else (left+up)//2 if f==3 else paeth(left,up,ul))
   v=(x-pred)&255; vals.append(abs(v if v<128 else v-256))
  scores.append(sum(vals))
 best=min(scores); choices=[i for i,v in enumerate(scores) if v==best]
 if len(choices)>1:ties.append((y,actual,choices,scores))
 prev=cur
print('tie rows:',len(ties),'candidate-pair counts:',dict(collections.Counter(tuple(t[2]) for t in ties)))
print('actual-vs-sorted-candidate bit counts:',dict(collections.Counter(int(t[1]!=min(t[2])) for t in ties)))
print('tie decisions (row,selected,possible) first 80:',[(y,actual,choices) for y,actual,choices,_ in ties[:80]])
bits=[int(actual!=min(choices)) for _,actual,choices,_ in ties]
for bitorder in ('big','little'):
 out=bytearray()
 for i in range(0,len(bits)-7,8):
  group=bits[i:i+8]
  if bitorder=='little':group=group[::-1]
  out.append(sum(v<<(7-j) for j,v in enumerate(group)))
 print('tie decision bytes',bitorder,':',out.hex(),'ascii:',repr(bytes(out)))
