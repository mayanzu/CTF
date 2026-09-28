import hashlib
import pathlib
import struct

path = pathlib.Path('/mnt/c/Users/mzj/Desktop/CTF/玄机刷题/题目资料/OpenHarmony_secret_561/hap_contents/ets/modules.abc')
data = path.read_bytes()
print('path:', path)
print('file bytes:', len(data))
print('SHA256:', hashlib.sha256(data).hexdigest())
print('magic:', data[:8])
for off in range(8, min(0x100, len(data)), 4):
    value = struct.unpack_from('<I', data, off)[0]
    print(f'header[{off:#04x}] = {value:#010x} ({value})')
print('final-page string offsets and raw byte windows:')
for marker in (b'HexStrTouint8Array', b'greetingStr', b'Go press the button to see the secret.', b'__Secret'):
    pos = data.find(marker)
    print(f'{marker!r}: offset={pos:#x}; preceding16={data[max(0,pos-16):pos].hex()}; following48={data[pos+len(marker):pos+len(marker)+48].hex()}')
