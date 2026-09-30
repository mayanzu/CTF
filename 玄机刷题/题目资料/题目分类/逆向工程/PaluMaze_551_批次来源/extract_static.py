from pathlib import Path
import struct,zlib,hashlib
p=Path(__file__).with_name('game_flag.exe')
d=p.read_bytes()
magic,plen,toff,tlen,pyver,dll=struct.unpack('!8sIIII64s',d[-88:])
start=len(d)-plen
toc=d[start+toff:start+toff+tlen]
pos=0
while pos<len(toc):
 size,off,stored,orig,compressed,typ=struct.unpack('!iIIIBc',toc[pos:pos+18])
 name=toc[pos+18:pos+size].split(b'\0',1)[0].decode()
 if name in ('game','PYZ-00.pyz'):
  raw=d[start+off:start+off+stored]
  raw=zlib.decompress(raw) if compressed else raw
  out=Path(__file__).with_name(name.replace('/','_')+'.bin')
  out.write_bytes(raw)
  print(name,'stored',stored,'original',orig,'decompressed',len(raw),'sha256',hashlib.sha256(raw).hexdigest(),'head',raw[:32].hex(),'path',out)
 pos+=size
