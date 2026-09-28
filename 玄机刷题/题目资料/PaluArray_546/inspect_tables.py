from pathlib import Path
import struct,sys
p=Path(sys.argv[1]);d=p.read_bytes();pe=struct.unpack_from("<I",d,0x3c)[0];o=pe+24;base=struct.unpack_from("<Q",d,o+24)[0];n=struct.unpack_from("<H",d,pe+6)[0];os=struct.unpack_from("<H",d,pe+20)[0];st=o+os;S=[]
for i in range(n):
 q=st+i*40;name=d[q:q+8].split(b"\0",1)[0].decode("ascii","replace");vs,rv,rs,rp=struct.unpack_from("<IIII",d,q+8);S.append((name,rv,rs,rp))
def va2fo(va):
 r=va-base
 for nm,rv,rs,rp in S:
  if rv<=r<rv+rs:return rp+r-rv
 raise ValueError(hex(va))
for va,size in ((0x140009040,0x100),(0x140005e00,0x100),(0x140005e60,0x90)):
 fo=va2fo(va);raw=d[fo:fo+size];print(f"--- VA=0x{va:x} file=0x{fo:x} ---");print(raw.hex(" "));print("ascii:","".join(chr(x) if 32<=x<127 else "." for x in raw));print("u16:",raw.decode("utf-16le",errors="replace"))
