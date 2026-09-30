import re,struct,sys
from pathlib import Path
b=Path(sys.argv[1]).read_bytes(); pe=struct.unpack_from('<I',b,0x3c)[0]; ns=struct.unpack_from('<H',b,pe+6)[0]; ol=struct.unpack_from('<H',b,pe+20)[0]; op=pe+24; img=struct.unpack_from('<Q',b,op+24)[0]; sb=op+ol
for i in range(ns):
 o=sb+i*40; name=b[o:o+8].split(b'\0',1)[0].decode('ascii','replace'); vs,va,rs,rp=struct.unpack_from('<IIII',b,o+8)
 if name=='.rdata':pass
# pcHeader
for m in re.finditer(struct.pack('<I',0xfffffff1),b):
 o=m.start()
 if o+72>len(b):continue
 p1,p2,lc,ps=b[o+4:o+8]; nf=struct.unpack_from('<Q',b,o+8)[0]; text=struct.unpack_from('<Q',b,o+24)[0]
 if not(p1 or p2) and lc in (1,2,4) and ps==8 and 100<=nf<=10000 and 0x400000<=text<0x800000:
  offs=struct.unpack_from('<6Q',b,o+32);break
pcln=o+offs[4]; names=o+offs[0]; ft=[struct.unpack_from('<II',b,pcln+8*i) for i in range(nf+1)]
def nm(fo):
 no=struct.unpack_from('<i',b,pcln+fo+4)[0]; x=names+no; end=b.find(b'\0',x);return b[x:end].decode('utf8','replace')
print('--- all math/rand and main functions with ranges ---')
for i,(e,fo) in enumerate(ft[:-1]):
 n=nm(fo)
 if n.startswith(('math/rand.','main.')): print(f'0x{text+e:x}-0x{text+ft[i+1][0]:x} {n}')
