from pathlib import Path
import contextlib,io,runpy,zlib,collections
script=Path(__file__).with_name('pixel_cage_filter_tie_channel.py')
with contextlib.redirect_stdout(io.StringIO()): ns=runpy.run_path(str(script))
ties=ns['ties'];p=Path(r'D:\Downloads\像素囚笼附件 (1)\challenge.png');b=p.read_bytes();pos=8;idat=bytearray()
while pos<len(b):
 n=int.from_bytes(b[pos:pos+4],'big');t=b[pos+4:pos+8];d=b[pos+8:pos+8+n]
 if t==b'IDAT':idat.extend(d)
 pos+=12+n
 if t==b'IEND':break
raw=zlib.decompress(idat);filters=[raw[y*(512*3+1)] for y in range(512)]
counts=collections.Counter()
examples=[]
for y,actual,choices,scores in ties:
 prev=filters[y-1] if y else None
 counts[('has_prev',prev is not None)]+=1
 counts[('same_as_prev',prev==actual)]+=1
 counts[('prev_is_candidate',prev in choices)]+=1
 if prev!=actual:examples.append((y,prev,actual,choices))
print('tie rows matching previous row filter:',sum(filters[y-1]==actual for y,actual,choices,_ in ties if y>0),'of',sum(y>0 for y,_,_,_ in ties),'non-first tie rows')
print('tie predecessor counts:',counts)
print('ties not matching previous filter:',examples[:30])
