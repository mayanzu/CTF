from pathlib import Path
from PIL import Image
import itertools, numpy as np
p=Path(r'D:\Downloads\像素囚笼附件 (1)\challenge.png')
a=np.asarray(Image.open(p).convert('RGB'))
H,W,_=a.shape
orders=list(itertools.permutations(range(3)))
scans={
 'row': lambda x:x.reshape(-1,3),
 'col': lambda x:x.transpose(1,0,2).reshape(-1,3),
 'row_serp': lambda x:np.concatenate([x[y] if y%2==0 else x[y,::-1] for y in range(H)],axis=0),
 'col_serp': lambda x:np.concatenate([x[:,col] if col%2==0 else x[::-1,col] for col in range(W)],axis=0),
}
def pack(bits,order):
    if order=='msb': pad=(-len(bits))%8; bits=np.pad(bits,(0,pad)); return np.packbits(bits,bitorder='big').tobytes()
    pad=(-len(bits))%8; bits=np.pad(bits,(0,pad)); return np.packbits(bits,bitorder='little').tobytes()
def runs(b):
    best=[]; cur=bytearray()
    for x in b:
        if 32<=x<127: cur.append(x)
        else:
            if len(cur)>len(best):best=cur
            cur=bytearray()
    if len(cur)>len(best):best=cur
    return bytes(best)
records=[]
for scan_name,scan_fn in scans.items():
    pix=scan_fn(a)
    for bit in range(8):
      for order in orders:
        seq=pix[:,order] if isinstance(order,tuple) else pix
        bits=((seq>>bit)&1).reshape(-1).astype(np.uint8)
        for endian in ('msb','lsb'):
            raw=pack(bits,endian)
            pr=sum(32<=x<127 for x in raw)/len(raw)
            best=runs(raw)
            if pr>.10 or b'flag' in raw.lower() or len(best)>=8:
                records.append((pr,len(best),scan_name,bit,''.join('RGB'[i] for i in order),endian,raw[:48].hex(),best[:80]))
# Three channel bits form one 3-bit symbol per pixel, then all symbols packed.
for scan_name,scan_fn in scans.items():
    pix=scan_fn(a)
    for bit in range(8):
      for order in orders:
        vals=np.zeros(len(pix),dtype=np.uint8)
        for j,ch in enumerate(order): vals |= ((pix[:,ch]>>bit)&1).astype(np.uint8) << (2-j)
        raw=pack(vals, 'msb')
        pr=sum(32<=x<127 for x in raw)/len(raw)
        best=runs(raw)
        if pr>.10 or b'flag' in raw.lower() or len(best)>=8:
            records.append((pr,len(best),scan_name,bit,''.join('RGB'[i] for i in order),'3bit',raw[:48].hex(),best[:80]))
records.sort(reverse=True)
print('image dimensions:',W,H)
print('candidate streams retained:',len(records))
for rec in records[:80]: print(rec)
