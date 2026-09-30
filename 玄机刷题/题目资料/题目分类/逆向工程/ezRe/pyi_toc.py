from pathlib import Path
import struct

path = Path('33.exe')
data = path.read_bytes()
cookie_size = 88
magic, pkg_len, toc_offset, toc_len, pyvers, py_lib = struct.unpack('!8sIIII64s', data[-cookie_size:])
expected_magic = b'MEI\014\013\012\013\016'
if magic != expected_magic:
    raise SystemExit(f'bad PyInstaller cookie magic: {magic!r}')
pkg_start = len(data) - pkg_len
toc_start = pkg_start + toc_offset
print('file_size =', len(data), 'archive_start =', hex(pkg_start))
print('toc_start =', hex(toc_start), 'toc_length =', toc_len, 'python_version =', pyvers)
print('python_library =', py_lib.split(b'\0', 1)[0].decode(errors='replace'))

cursor = toc_start
limit = toc_start + toc_len
entries = []
while cursor < limit:
    entry_size = struct.unpack('!I', data[cursor:cursor + 4])[0]
    if entry_size < 18 or cursor + entry_size > limit:
        raise SystemExit(f'invalid TOC entry size {entry_size} at {hex(cursor)}')
    offset, compressed_size, uncompressed_size = struct.unpack('!III', data[cursor + 4:cursor + 16])
    compressed = data[cursor + 16]
    typecode = data[cursor + 17:cursor + 18].decode(errors='replace')
    name = data[cursor + 18:cursor + entry_size].split(b'\0', 1)[0].decode(errors='replace')
    entries.append((name, offset, compressed_size, uncompressed_size, compressed, typecode))
    cursor += entry_size
if cursor != limit:
    raise SystemExit(f'TOC parse ended at {hex(cursor)}, expected {hex(limit)}')
print('entry_count =', len(entries))
for row in entries:
    print(row)
