from pathlib import Path
import struct
p=Path('PaluArray_flag_unpacked.exe'); d=p.read_bytes()
for k in [0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf]:
 b=struct.pack('<I',k); offs=[]; i=0
 while (i:=d.find(b,i))>=0: offs.append(i); i+=1
 print(f'{k:08x}: file_offsets={[hex(x) for x in offs]}')
