from pathlib import Path
from PIL import Image
import numpy as np
src=Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
a=np.array(Image.open(src).convert('RGB'))
out=Path('.')
print('Unique RGB colors:',len(np.unique(a.reshape(-1,3),axis=0)))
for ci,name in enumerate('RGB'):
    bits=(a[:,:,ci]&1).astype(np.uint8)
    vals,counts=np.unique(bits,return_counts=True)
    seq=bits.reshape(-1)
    packed=np.packbits(seq,bitorder='big').tobytes()
    printable=sum(32<=x<127 for x in packed)/len(packed)
    preview=packed[:64]
    print(name,'LSB counts',dict(zip(vals.tolist(),counts.tolist())),'printable byte ratio',round(printable,3),'first bytes',preview.hex(' '))
    Image.fromarray(bits*255).save(out/f'pixel_cage_{name.lower()}_lsb.png')
