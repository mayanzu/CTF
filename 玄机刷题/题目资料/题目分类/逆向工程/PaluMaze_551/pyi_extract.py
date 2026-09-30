from pathlib import Path
import struct, zlib
source = Path(r'D:\Downloads\game_flag.exe')
out = Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\PaluMaze_551\extracted')
data = source.read_bytes()
magic = b'MEI' + bytes([12, 11, 10, 11, 14])
cookie_at = data.rfind(magic)
if cookie_at < 0:
    raise SystemExit('PyInstaller cookie not found')
fields = struct.unpack('!8sIIII64s', data[cookie_at:cookie_at + 88])
pkg_len, toc_offset, toc_len, pyvers, pylib = fields[1:]
archive_start = len(data) - pkg_len
overlay = data[archive_start:cookie_at]
print(f'cookie_offset=0x{cookie_at:x} package_length={pkg_len} pyinstaller_python={pyvers} python_library={pylib.split(bytes([0]))[0].decode()}')
print(f'archive_start=0x{archive_start:x} toc_offset={toc_offset} toc_length={toc_len}')
pos = toc_offset
end = pos + toc_len
count = 0
while pos < end:
    entry_size = struct.unpack('!I', overlay[pos:pos + 4])[0]
    offset, compressed_len, uncompressed_len, compressed, typecode = struct.unpack('!IIIBc', overlay[pos + 4:pos + 18])
    name = overlay[pos + 18:pos + entry_size].split(bytes([0]))[0].decode('utf-8', 'replace')
    packed = overlay[offset:offset + compressed_len]
    content = zlib.decompress(packed) if compressed else packed
    if len(content) != uncompressed_len:
        raise ValueError(f'{name}: size mismatch {len(content)} != {uncompressed_len}')
    dest = (out / name).resolve()
    if out.resolve() not in dest.parents and dest != out.resolve():
        raise ValueError(f'unsafe path in archive: {name}')
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(content)
    print(f'{count:03d} type={typecode.decode(errors="replace")} compressed={compressed} offset={offset} packed={compressed_len} unpacked={uncompressed_len} name={name}')
    count += 1
    pos += entry_size
if pos != end:
    raise ValueError(f'TOC parse ended at {pos}, expected {end}')
print(f'extracted_entries={count} output={out}')
