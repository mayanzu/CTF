from pathlib import Path
import hashlib,zlib
r=Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\butterfly_552")
bin=(r/'analysis/extracted/butterfly').read_bytes()
key=(r/'analysis/extracted/encode.dat.key').read_bytes()
dat=(r/'analysis/extracted/encode.dat').read_bytes()
fileoff=0x825b6; va=0x4825b6; n=32
print(f'rodata fileoff=0x{fileoff:x}, VA=0x{va:x}, length={n}')
print('binary bytes:',bin[fileoff:fileoff+n].hex())
print('binary ascii:',repr(bin[fileoff:fileoff+n]))
print('key file:',key.hex(),repr(key))
print('key_file_equals_rodata_32=',key==bin[fileoff:fileoff+n])
print('key first8=',key[:8].hex(),repr(key[:8]))
print('encode.dat len=',len(dat),'hex=',dat.hex())
print('encode.dat last bytes offsets32..35:',[(i,dat[i]) for i in range(32,len(dat))])
for f in [r/'originals/butterfly.7z',r/'analysis/extracted/butterfly',r/'analysis/extracted/encode.dat',r/'analysis/extracted/encode.dat.key']:
 if f.exists():
  x=f.read_bytes(); print(f.name,'length',len(x),'crc32',f'{zlib.crc32(x)&0xffffffff:08X}','sha256',hashlib.sha256(x).hexdigest().upper())
