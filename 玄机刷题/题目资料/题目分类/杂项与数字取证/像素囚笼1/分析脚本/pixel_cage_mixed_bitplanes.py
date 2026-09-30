from pathlib import Path
from PIL import Image
import itertools,numpy as np
img=np.asarray(Image.open(Path(r'D:\Downloads\像素囚笼附件 (1)\challenge.png')).convert('RGB'))
scans={'row':img.reshape(-1,3),'col':img.transpose(1,0,2).reshape(-1,3)}
max_rec=(0,None,None,None,None)
hits=[]; total=0
for scan_name,pix in scans.items():
  planes={(ch,bit):((pix[:,ch]>>bit)&1).astype(np.uint8) for ch in range(3) for bit in range(8)}
  for bitsel in itertools.product(range(8),repeat=3):
    for order in itertools.permutations(range(3)):
      bits=np.stack([planes[(ch,bitsel[ch])] for ch in order],axis=1).reshape(-1)
      raw=np.packbits(bits,bitorder='big').tobytes(); total+=1
      arr=np.frombuffer(raw,dtype=np.uint8)
      printable=float(np.count_nonzero((arr>=32)&(arr<127)))/len(arr)
      if printable>max_rec[0]:max_rec=(printable,scan_name,bitsel,''.join('RGB'[i] for i in order),raw[:48].hex())
      low=raw.lower()
      for token in (b'flag{',b'xj{',b'mzj',b'secret'):
        if token in low:hits.append((scan_name,bitsel,order,token,low.find(token)))
print('full mixed bit-plane count:',total,'image=',img.shape[1],img.shape[0])
print('literal token hits [flag{, xj{, mzj, secret]:',hits)
print('maximum printable-byte ratio:',max_rec)
