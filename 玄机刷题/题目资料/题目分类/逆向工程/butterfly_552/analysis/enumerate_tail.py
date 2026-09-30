from pathlib import Path
from itertools import product
root=Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\butterfly_552\analysis\extracted")
cipher=(root/"encode.dat").read_bytes()
k=(root/"encode.dat.key").read_bytes()[:8]
ct=cipher[32:36]
chars=b"0123456789abcdefABCDEF"
def enc(block):
    z=[block[i]^k[i] for i in range(8)]
    w=[z[i^1] for i in range(8)]
    q=int.from_bytes(bytes(w),"little")
    q=((q<<1)|(q>>63))&((1<<64)-1)
    x=q.to_bytes(8,"little")
    return bytes((x[i]+k[i])&255 for i in range(8))
print("target final ciphertext:",ct.hex())
print("known appended little-endian input length bytes:",bytes([len(cipher)&255,(len(cipher)>>8)&255]).hex())
hits=[]
for tail in product(chars, repeat=3):
    p=bytes(tail)+b"}"
    # main writes file size at buffer[file_size:file_size+2] before encrypting.
    # Bytes 38..39 are uninitialized, but only byte 38's top bit affects output byte 0.
    for p6msb in (0,1):
        block=p+bytes([len(cipher)&255,(len(cipher)>>8)&255,p6msb<<7,0])
        out=enc(block)[:4]
        if out==ct:
            hits.append((p,p6msb,block.hex(),out.hex()))
print("candidate suffixes matching all 4 available ciphertext bytes:",len(hits))
for h in hits[:40]: print("suffix",repr(h[0]),"pad[6].msb",h[1],"input_block",h[2],"forward",h[3])
