from itertools import product
from pathlib import Path
from time import perf_counter
from zipfile import ZipFile, _ZipDecrypter
archive=Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
colors=['blue','red','yellow','green','purple','cyan']
with ZipFile(archive) as z:
 info=z.getinfo('secret.txt'); raw=archive.read_bytes(); n=int.from_bytes(raw[info.header_offset+26:info.header_offset+28],'little'); x=int.from_bytes(raw[info.header_offset+28:info.header_offset+30],'little'); pos=info.header_offset+30+n+x; header=raw[pos:pos+12]; check=(info.CRC>>24)&255
 start=perf_counter(); tries=0
 print('Enumerating color-name sequences of 1..8 names (case-sensitive lowercase).')
 for length in range(1,9):
  for seq in product(colors,repeat=length):
   pw=''.join(seq).encode(); tries+=1
   if _ZipDecrypter(pw)(header)[-1]!=check: continue
   try: data=z.read(info,pwd=pw)
   except Exception: continue
   print('PASSWORD FOUND:',pw.decode()); print('SECRET.TXT:',data.decode(errors='replace')); raise SystemExit
 print('No match after',tries,'candidates; seconds=',round(perf_counter()-start,2))
