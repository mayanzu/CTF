from pathlib import Path
from PIL import Image
import numpy as np
im=np.array(Image.open(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png')).convert('RGB'))
for ch,name in enumerate('RGB'):
 for bit in range(8):
  plane=((im[:,:,ch]>>bit)&1).astype(np.uint8)
  raw=np.packbits(plane.reshape(-1),bitorder='big').tobytes()
  ratio=sum(32<=v<127 for v in raw)/len(raw)
  print(f'{name} bit{bit}: ones={int(plane.sum())} printable={ratio:.3f} first={raw[:8].hex()}')
