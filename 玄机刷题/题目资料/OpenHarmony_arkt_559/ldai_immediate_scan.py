import struct
from pathlib import Path
b=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\OpenHarmony_arkt_559\附件解包\HAP内容\ets\modules.abc').read_bytes()
print('SCAN_OFFSET_RANGE=0x2700..0x5638')
for i in range(0x2700,len(b)-5):
    if b[i]==0x62:
        v=struct.unpack_from('<i',b,i+1)[0]
        if -1000000<=v<=1000000000:
            print(f'offset=0x{i:04x} imm32={v} raw={b[i:i+5].hex()}')
