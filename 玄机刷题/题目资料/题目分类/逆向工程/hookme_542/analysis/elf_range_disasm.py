from pathlib import Path
import struct
from capstone import *
root=Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\hookme_542")
path=root/"analysis"/"components"/"lib"/"arm64-v8a"/"libhookme.so"
b=path.read_bytes(); shoff=struct.unpack_from("<Q",b,40)[0]; ents=struct.unpack_from("<H",b,58)[0]; n=struct.unpack_from("<H",b,60)[0]; si=struct.unpack_from("<H",b,62)[0]
raw=[struct.unpack_from("<IIQQQQIIQQ",b,shoff+i*ents) for i in range(n)]
strtab=b[raw[si][4]:raw[si][4]+raw[si][5]]
text=None
for s in raw:
    e=strtab.find(b"\0",s[0]); name=strtab[s[0]:e].decode("ascii","ignore")
    if name==".text": text={"addr":s[3],"off":s[4],"size":s[5]}
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
ranges=[(0x2ed00,0x2ef80),(0x2ef80,0x2f160),(0x2f600,0x2f740)]
lines=[]
for lo,hi in ranges:
    off=text['off']+lo-text['addr']; code=b[off:off+hi-lo]
    lines.append(f"\n===== file {path} VA 0x{lo:x}-0x{hi:x} =====")
    lines += [f"{i.address:08x}: {i.mnemonic:<10} {i.op_str}" for i in md.disasm(code,lo)]
out=root/"analysis"/"native"/"arm64-v8a_selected_ranges.txt"
out.write_text("\n".join(lines)+"\n",encoding="utf-8")
print(out)
