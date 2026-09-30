import pathlib,struct,sys
b=pathlib.Path(sys.argv[1]).read_bytes(); u32=lambda o:struct.unpack_from('<I',b,o)[0]
pe=u32(0x3c); sh=pe+24+struct.unpack_from('<H',b,pe+20)[0]; ss=[]
for i in range(struct.unpack_from('<H',b,pe+6)[0]):
 s=sh+40*i; name=b[s:s+8].split(b'\0')[0].decode(); vs,va,rs,rp=struct.unpack_from('<IIII',b,s+8);ss.append((name,va,max(vs,rs),rp))
def va2off(va):
 rva=va-0x400000
 for nm,va0,sz,rp in ss:
  if va0<=rva<va0+sz:return rp+rva-va0
 raise ValueError(hex(va))
for va,n in [(0x4cb69e,36),(0x4cb405,35)]:
 o=va2off(va); x=b[o:o+n]; print(f'VA=0x{va:x} raw=0x{o:x} length={n} repr={x!r} ascii={x.decode()} int={int(x.decode())}')
