from pathlib import Path
import struct
import zlib

source = Path('33.exe')
blob = source.read_bytes()
magic, pkg_len, toc_offset, toc_len, pyvers, py_lib = struct.unpack('!8sIIII64s', blob[-88:])
if magic != b'MEI\014\013\012\013\016':
    raise SystemExit('PyInstaller cookie not found')
pkg_start = len(blob) - pkg_len
toc_pos = pkg_start + toc_offset
toc_end = toc_pos + toc_len
out = Path('pyi_extracted')
out.mkdir(exist_ok=True)
count = 0
while toc_pos < toc_end:
    entry_size = struct.unpack('!I', blob[toc_pos:toc_pos + 4])[0]
    offset, csize, usize = struct.unpack('!III', blob[toc_pos + 4:toc_pos + 16])
    compressed, kind = blob[toc_pos + 16], blob[toc_pos + 17:toc_pos + 18].decode()
    name = blob[toc_pos + 18:toc_pos + entry_size].split(b'\0', 1)[0].decode(errors='replace')
    toc_pos += entry_size
    if kind == 'o':
        continue
    payload = blob[pkg_start + offset:pkg_start + offset + csize]
    if compressed:
        payload = zlib.decompress(payload)
    if len(payload) != usize:
        raise SystemExit(f'{name}: got {len(payload)} bytes, expected {usize}')
    safe_name = name.replace('/', '_').replace('\\', '_')
    suffix = '.marshal' if kind == 's' else '.bin'
    (out / (safe_name + suffix)).write_bytes(payload)
    count += 1
    print(f'{name}: {len(payload)} bytes type={kind}')
print('extracted entries =', count, 'to', out.resolve())
