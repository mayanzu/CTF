from pathlib import Path
from PIL import Image
import numpy as np
from collections import Counter
import hashlib
p=Path(__file__).resolve().parents[1]/'附件'/'challenge.png'
im=Image.open(p).convert('RGB'); a=np.asarray(im,dtype=np.uint8); h,w,_=a.shape; n=h*w
print('image=',w,h,'RGB bytes=',a.nbytes,'palette=',Counter(map(tuple,a.reshape(-1,3))).most_common())
# Row/column, reverse, alternating serpentine, and diagonal traversals.
idx=np.arange(n,dtype=np.int64).reshape(h,w)
orders={
 'row':idx.ravel(), 'row_reverse':idx.ravel()[::-1],
 'column':idx.T.ravel(), 'column_reverse':idx.T.ravel()[::-1],
 'row_serpentine':np.concatenate([idx[y] if y%2==0 else idx[y,::-1] for y in range(h)]),
 'column_serpentine':np.concatenate([idx[:,x] if x%2==0 else idx[::-1,x] for x in range(w)]),
 'diagonal':np.array(sorted(range(n),key=lambda q:((q//w+q%w),q%w)),dtype=np.int64),
 'anti_diagonal':np.array(sorted(range(n),key=lambda q:((q//w-(q%w)),q%w)),dtype=np.int64),
}
flat=a.reshape(-1,3); wide=flat.astype(np.uint32)
features={
 'R':flat[:,0], 'G':flat[:,1], 'B':flat[:,2],
 'RxorG':np.bitwise_xor(flat[:,0],flat[:,1]),
 'GxorB':np.bitwise_xor(flat[:,1],flat[:,2]),
 'BxorR':np.bitwise_xor(flat[:,2],flat[:,0]),
 'RGBsum_mod256':(flat[:,0].astype(np.uint16)+flat[:,1]+flat[:,2]).astype(np.uint8),
 'luma601':((299*wide[:,0]+587*wide[:,1]+114*wide[:,2])//1000).astype(np.uint8),
 'RminusG':(flat[:,0].astype(np.int16)-flat[:,1]).astype(np.uint8),
 'GminusB':(flat[:,1].astype(np.int16)-flat[:,2]).astype(np.uint8),
}
# Palette index under deterministic first-seen and RGB-sort orders; only a small exact map, not all permutations.
pal_first=list(dict.fromkeys(map(tuple,flat.tolist())))
for label,pal in [('index_first_seen',pal_first),('index_rgb_sorted',sorted(pal_first))]:
    mp={c:i for i,c in enumerate(pal)}
    features[label]=np.array([mp[tuple(x)] for x in flat],dtype=np.uint8)
marker_hits=[]; ranked=[]; seen=set(); total=0
for oname,order in orders.items():
    for fname,values in features.items():
        v=values[order]
        for bit in range(8):
            bits=((v>>bit)&1).astype(np.uint8)
            for byteorder in ('big','little'):
                stream=np.packbits(bits,bitorder=byteorder).tobytes()
                key=hashlib.sha1(stream).digest()
                if key in seen: continue
                seen.add(key); total+=1
                for needle in (b'flag{',b'flag',b'xj{',b'secret',b'ctf{'):
                    if needle.lower() in stream.lower(): marker_hits.append((oname,fname,bit,byteorder,needle))
                printable=sum(32<=c<127 for c in stream)/len(stream)
                ranked.append((printable,oname,fname,bit,byteorder,stream[:24]))
print('unique packed streams checked=',total,'marker hits=',marker_hits)
for row in sorted(ranked,reverse=True)[:12]:
    ratio,oname,fname,bit,bo,head=row
    print(f'top printable={ratio:.4f} traversal={oname} feature={fname} bit={bit} pack={bo} head={head.hex()} ascii={repr(head.decode("ascii","backslashreplace"))}')


