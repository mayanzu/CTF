from pathlib import Path
import struct, zlib
source=Path(r'D:\Downloads\game_flag (1).exe')
out=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluMaze_551_fresh\archive')
data=source.read_bytes()
magic=b'MEI'+bytes((12,11,10,11,14))
loc=data.rfind(magic)
if loc<0: raise SystemExit('PyInstaller v6 cookie not found')
raw=data[loc:loc+88]
if len(raw)!=88: raise SystemExit(f'truncated cookie: {len(raw)} bytes')
fields=struct.unpack('!8sIIII64s',raw)
pkg_len,toc_offset,toc_len,pyvers,pylib=fields[1:]
start=len(data)-pkg_len
archive=data[start:loc]
print(f'source_bytes={len(data)} cookie_offset=0x{loc:x}')
print(f'archive_start=0x{start:x} package_len={pkg_len} pyinstaller_python={pyvers} python_dll={pylib.split(bytes((0,)))[0].decode(errors="replace")}')
print(f'toc_offset={toc_offset} toc_length={toc_len} archive_payload_len={len(archive)}')
entries=[]; pos=toc_offset; end=pos+toc_len
while pos<end:
    size=struct.unpack('!I',archive[pos:pos+4])[0]
    if size<18 or pos+size>end: raise SystemExit(f'invalid TOC entry at {pos}: size={size}')
    offset,clen,ulen,compressed,kind=struct.unpack('!IIIBc',archive[pos+4:pos+18])
    name=archive[pos+18:pos+size].split(bytes((0,)),1)[0].decode('utf-8','replace')
    entries.append((name,kind.decode('ascii','replace'),compressed,offset,clen,ulen))
    pos+=size
print('entry_count=',len(entries))
for name,kind,c,off,clen,ulen in entries:
    print(f'ENTRY type={kind!r} compressed={c} offset={off} compressed_len={clen} raw_len={ulen} name={name!r}')
print('FLAG_NAME_MATCHES=',[e for e in entries if 'flag' in e[0].lower()])
print('PATH_NAME_MATCHES=',[e for e in entries if e[0].lower() in ('/flag','flag','flag.txt') or 'flag' in e[0].lower()])
for name,kind,c,off,clen,ulen in entries:
    if name in ('game','game.pyc','flag','flag.txt') or 'flag' in name.lower():
        blob=archive[off:off+clen]
        content=zlib.decompress(blob) if c else blob
        if len(content)!=ulen: raise SystemExit(f'length mismatch in {name}: {len(content)} != {ulen}')
        dest=out/(name.replace('/','_').replace('\\','_'))
        dest.parent.mkdir(parents=True,exist_ok=True); dest.write_bytes(content)
        print(f'EXTRACTED {name!r} bytes={len(content)} -> {dest}')
