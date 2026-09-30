from pathlib import Path
import hashlib, struct
src = Path(__file__).resolve().parent / 'ezbase.exe'
dst = Path(__file__).resolve().parent / 'ezbase_names_restored.exe'
b = bytearray(src.read_bytes())
pe = struct.unpack_from('<I', b, 0x3c)[0]
n = struct.unpack_from('<H', b, pe + 6)[0]
opt_size = struct.unpack_from('<H', b, pe + 20)[0]
sec = pe + 24 + opt_size
expected = [b'PXU0', b'PXU1', b'UXP2']
replacement = [b'UPX0', b'UPX1', b'UPX2']
assert n == 3, f'unexpected section count: {n}'
for i, (old, new) in enumerate(zip(expected, replacement)):
    off = sec + i * 40
    got = bytes(b[off:off+8]).split(b'\0', 1)[0]
    assert got == old, (i, got, old)
    b[off:off+8] = new.ljust(8, b'\0')
dst.write_bytes(b)
print(f'input={src} bytes={len(src.read_bytes())} sha256={hashlib.sha256(src.read_bytes()).hexdigest().upper()}')
print(f'patched={dst} bytes={len(b)} sha256={hashlib.sha256(b).hexdigest().upper()}')
print('section names:', [bytes(b[sec+i*40:sec+i*40+8]).split(b'\0',1)[0].decode() for i in range(n)])
