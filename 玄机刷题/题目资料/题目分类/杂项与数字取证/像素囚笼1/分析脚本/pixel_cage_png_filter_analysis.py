from pathlib import Path
import struct, zlib, collections
p = Path(r'D:\Downloads\像素囚笼附件 (1)\challenge.png')
b = p.read_bytes()
assert b[:8] == b'\x89PNG\r\n\x1a\n'
pos = 8
chunks = []
idat = bytearray()
while pos < len(b):
    n = int.from_bytes(b[pos:pos+4], 'big')
    typ = b[pos+4:pos+8]
    data = b[pos+8:pos+8+n]
    crc = int.from_bytes(b[pos+8+n:pos+12+n], 'big')
    chunks.append((typ.decode('ascii'), n, crc == zlib.crc32(typ+data)))
    if typ == b'IHDR':
        width, height, depth, ctype, comp, filt, interlace = struct.unpack('>IIBBBBB', data)
    if typ == b'IDAT': idat.extend(data)
    pos += 12+n
    if typ == b'IEND': break
raw = zlib.decompress(idat)
channels = {0:1,2:3,4:2,6:4}[ctype]
stride = width*channels
assert len(raw) == height*(stride+1)
filters = [raw[y*(stride+1)] for y in range(height)]
print('Chunks (name,length,CRC-valid):', chunks)
print('IHDR:', width, height, depth, ctype, comp, filt, interlace)
print('IDAT compressed bytes:', len(idat), 'decompressed scanline bytes:', len(raw))
print('Filter counts:', dict(collections.Counter(filters)))
print('Filter sequence first 160:', ''.join(map(str,filters[:160])))
print('Filter sequence changes:', [(i,filters[i]) for i in range(1,len(filters)) if filters[i]!=filters[i-1]][:120])
for mapping_name, mapping in [('raw01234','01234'),('alpha',' abcde')]:
    s=''.join(mapping[v] for v in filters)
    print(mapping_name, 'ascii-ish:', repr(s[:160]))
# Test row filter IDs as little bit planes, with 0/1, low bit and parity sequences.
for bit in range(3):
    bits=[(v>>bit)&1 for v in filters]
    for msb in (True,False):
        out=bytearray()
        for i in range(0,len(bits)-7,8):
            group=bits[i:i+8]
            if not msb: group=group[::-1]
            out.append(sum(x<<(7-j) for j,x in enumerate(group)))
        print('filter-bit',bit,'msb',msb,'bytes',out[:64].hex(), 'printable%', round(sum(32<=x<127 for x in out)/len(out),3))
