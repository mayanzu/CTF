import struct
from pathlib import Path
b=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\OpenHarmony_arkt_559\附件解包\HAP内容\ets\modules.abc').read_bytes()
for n in [7,271,277,42583,74520,75067]:
 for width in [2,4,8]:
  if n >= 1 << (8*width): continue
  x=n.to_bytes(width,'little')
  pos=[i for i in range(len(b)) if b.startswith(x,i)]
  if pos: print(f'value={n} width={width} bytes={x.hex()} offsets={[hex(i) for i in pos]}')
