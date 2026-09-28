from pathlib import Path
import struct,zlib,collections
PNG=Path(r'D:\Downloads\像素囚笼附件 (1)\challenge.png')
b=PNG.read_bytes(); assert b[:8]==b'\x89PNG\r\n\x1a\n'
pos=8; idat=bytearray(); chunks=[]
while pos<len(b):
 n=int.from_bytes(b[pos:pos+4],'big'); t=b[pos+4:pos+8]; d=b[pos+8:pos+8+n]; crc=int.from_bytes(b[pos+8+n:pos+12+n],'big')
 chunks.append((t.decode(),n,crc==zlib.crc32(t+d)))
 if t==b'IDAT':idat.extend(d)
 pos+=12+n
 if t==b'IEND':break
zdata=bytes(idat); assert len(zdata)>=6
cmf,flg=zdata[0],zdata[1]
rawdef=zdata[2:-4]
adler=int.from_bytes(zdata[-4:],'big')
print('PNG chunks:',chunks)
print('zlib header:',hex(cmf),hex(flg),'FCHECK-valid:',(cmf*256+flg)%31==0,'FLEVEL:',flg>>6,'FDICT:',bool(flg&32))
print('IDAT length:',len(zdata),'deflate payload bytes:',len(rawdef),'Adler trailer:',hex(adler),'computed:',hex(zlib.adler32(zlib.decompress(zdata))))
obj=zlib.decompressobj(-15); out=obj.decompress(rawdef); out+=obj.flush()
print('raw inflate: bytes=',len(out),'eof=',obj.eof,'unused_data=',len(obj.unused_data),'unconsumed_tail=',len(obj.unconsumed_tail))

class Bits:
 def __init__(self,data):self.d=data;self.p=0
 def read(self,n):
  if self.p+n>len(self.d)*8: raise EOFError(f'need {n} bits at {self.p}')
  v=0
  for i in range(n): v |= ((self.d[(self.p+i)//8]>>((self.p+i)%8))&1)<<i
  self.p+=n;return v
 def align(self):self.p=(self.p+7)&~7

def huffman(lengths):
 maxlen=max(lengths,default=0); counts=[0]*(maxlen+1)
 for n in lengths:
  if n:counts[n]+=1
 nxt=[0]*(maxlen+1); code=0
 for bits in range(1,maxlen+1):
  code=(code+counts[bits-1])<<1;nxt[bits]=code
 table={}
 for sym,n in enumerate(lengths):
  if n:
   c=nxt[n];nxt[n]+=1;table[(n,c)]=sym
 return table,maxlen

def symread(r,h):
 table,m=h; code=0
 for n in range(1,m+1):
  code=(code<<1)|r.read(1)
  hit=table.get((n,code))
  if hit is not None:return hit
 raise ValueError(f'invalid Huffman code at {r.p}')

def fixed():
 ll=[8]*144+[9]*112+[7]*24+[8]*8; dd=[5]*32
 return huffman(ll),huffman(dd)

LEN_BASE=[3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258]
LEN_EXTRA=[0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0]
DIST_BASE=[1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577]
DIST_EXTRA=[0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13]

def dynamic(r):
 hlit=r.read(5)+257;hdist=r.read(5)+1;hclen=r.read(4)+4
 order=[16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15]
 cl=[0]*19
 for i in range(hclen):cl[order[i]]=r.read(3)
 ch=huffman(cl); lengths=[]
 while len(lengths)<hlit+hdist:
  s=symread(r,ch)
  if s<=15:lengths.append(s)
  elif s==16:
   rep=r.read(2)+3
   if not lengths:raise ValueError('repeat previous with no prior code length')
   lengths.extend([lengths[-1]]*rep)
  elif s==17:lengths.extend([0]*(r.read(3)+3))
  elif s==18:lengths.extend([0]*(r.read(7)+11))
  if len(lengths)>hlit+hdist:raise ValueError('code lengths overrun')
 return huffman(lengths[:hlit]),huffman(lengths[hlit:])

r=Bits(rawdef); decoded=bytearray(); blocks=[]; final=False
while not final:
 start=r.p; final=bool(r.read(1)); typ=r.read(2); literals=0;matches=0;block_out_start=len(decoded)
 if typ==0:
  r.align(); n=r.read(16);nn=r.read(16)
  if (n^0xffff)!=nn:raise ValueError('bad stored LEN/NLEN')
  for _ in range(n):decoded.append(r.read(8))
 elif typ in (1,2):
  lh,dh=fixed() if typ==1 else dynamic(r)
  while True:
   s=symread(r,lh)
   if s<256:decoded.append(s);literals+=1
   elif s==256:break
   elif s<=285:
    ix=s-257;length=LEN_BASE[ix]+r.read(LEN_EXTRA[ix]);ds=symread(r,dh)
    if ds>29:raise ValueError('reserved distance symbol')
    dist=DIST_BASE[ds]+r.read(DIST_EXTRA[ds])
    if dist>len(decoded):raise ValueError('distance exceeds output')
    for _ in range(length):decoded.append(decoded[-dist])
    matches+=1
   else:raise ValueError('reserved length symbol')
 else:raise ValueError('reserved BTYPE=3')
 blocks.append({'final':int(final),'type':typ,'start_bit':start,'end_bit':r.p,'literal_symbols':literals,'match_symbols':matches,'out_bytes':len(decoded)-block_out_start})
print('manual deflate block parse:',blocks)
print('manual/raw-zlib outputs equal:',bytes(decoded)==out,'decoded length:',len(decoded))
end_bit=r.p; pad=(8-end_bit%8)%8
padval=r.read(pad) if pad else 0
remaining=rawdef[r.p//8:]
print('final EOB bit:',end_bit,'padding bit count:',pad,'padding value (LSB-first):',bin(padval),'whole bytes after final block:',len(remaining),remaining.hex())
