from pathlib import Path
import base64, binascii, hashlib, re, struct, zipfile, zlib
root = Path(__file__).resolve().parents[1]
image = root / '附件' / 'challenge.png'
blob = image.read_bytes()
print('Image SHA256:', hashlib.sha256(blob).hexdigest())
with zipfile.ZipFile(image) as archive:
    item = archive.getinfo('secret.txt')
    assert item.compress_type == 8
    name_len, extra_len = struct.unpack_from('<HH', blob, item.header_offset + 26)
    data_offset = item.header_offset + 30 + name_len + extra_len
    payload = blob[data_offset:data_offset + item.compress_size]
    print('Flag bits:', item.flag_bits, 'Payload offset:', data_offset, 'Payload length:', len(payload))
    inflater = zlib.decompressobj(-15)
    plaintext = inflater.decompress(payload) + inflater.flush()
    assert inflater.eof and not inflater.unused_data and not inflater.unconsumed_tail
    assert len(plaintext) == item.file_size
    assert (binascii.crc32(plaintext) & 0xffffffff) == item.CRC
    print('CRC32 verified:', f'{item.CRC:08x}', 'Plaintext length:', len(plaintext))
    print(plaintext.decode('ascii'))
    encoded = plaintext.splitlines()[-1]
    flag = base64.b64decode(encoded, validate=True)
    assert re.fullmatch(rb'flag\{[0-9a-f]{32}\}', flag)
    print('FLAG:', flag.decode('ascii'))
    (root / '分析脚本' / 'recovered_secret.txt').write_bytes(plaintext)
    print('Saved recovered_secret.txt; original PNG unchanged.')
