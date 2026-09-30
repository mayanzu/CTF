import struct
from pathlib import Path
p=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\OpenHarmony_arkt_559\附件解包\HAP内容\ets\modules.abc')
b=p.read_bytes()

def uleb(x):
    out=[]
    while True:
        t=x&0x7f;x>>=7
        out.append(t|(0x80 if x else 0))
        if not x:return bytes(out)

def needle_offsets(x):
    patterns={
        'u8':x.to_bytes(1,'little',signed=False) if x<256 else None,
        'u16le':x.to_bytes(2,'little',signed=False) if x<65536 else None,
        'u32le':x.to_bytes(4,'little',signed=False),
        'u64le':x.to_bytes(8,'little',signed=False),
        'f64le':struct.pack('<d',float(x)),
        'uleb':uleb(x),
    }
    for kind,pat in patterns.items():
        if pat:
            starts=[];pos=0
            while True:
                pos=b.find(pat,pos)
                if pos<0:break
                starts.append(pos);pos+=1
            if starts:print(f'value={x} form={kind} bytes={pat.hex()} offsets={[hex(o) for o in starts]}')
for n in [7,17,271,277,42583,74520,75067,73746,6883,48970]:needle_offsets(n)
print('FLOAT64_ALIGNED_CANDIDATES:')
for offset in range(0,len(b)-7,8):
    val=struct.unpack_from('<d',b,offset)[0]
    if val in (7.0,17.0,271.0,277.0,42583.0,74520.0,75067.0):print(hex(offset),val)
