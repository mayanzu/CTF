from pathlib import Path
import struct
root=Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\hookme_542")
path=root/"analysis"/"components"/"lib"/"arm64-v8a"/"libhookme.so"
b=path.read_bytes(); shoff=struct.unpack_from("<Q",b,40)[0]; es=struct.unpack_from("<H",b,58)[0]; n=struct.unpack_from("<H",b,60)[0]; si=struct.unpack_from("<H",b,62)[0]
raw=[struct.unpack_from("<IIQQQQIIQQ",b,shoff+i*es) for i in range(n)]
shstr=b[raw[si][4]:raw[si][4]+raw[si][5]]
secs=[]
for i,s in enumerate(raw):
    e=shstr.find(b"\0",s[0]); name=shstr[s[0]:e].decode("ascii","replace")
    secs.append({"name":name,"type":s[1],"addr":s[3],"off":s[4],"size":s[5],"link":s[6],"entsize":s[9]})
plt=next(s for s in secs if s["name"]==".plt")
relsec=next(s for s in secs if s["name"]==".rela.plt")
dynsym=next(s for s in secs if s["name"]==".dynsym"); dynstr=next(s for s in secs if s["name"]==".dynstr")
st=b[dynstr['off']:dynstr['off']+dynstr['size']]
syms=[]
for off in range(dynsym['off'],dynsym['off']+dynsym['size'],dynsym['entsize']):
    no,info,other,shndx,val,size=struct.unpack_from("<IBBHQQ",b,off)
    e=st.find(b"\0",no); syms.append(st[no:e].decode("utf-8","replace") if no<len(st) else "")
rows=[f".plt addr=0x{plt['addr']:x} size=0x{plt['size']:x}; AArch64 PLT0 header=0x20, entry=0x10", "Relocation-to-PLT map:"]
for i,off in enumerate(range(relsec['off'],relsec['off']+relsec['size'],relsec['entsize'])):
    ro,info,add=struct.unpack_from("<QQq",b,off); idx=info>>32; name=syms[idx] if idx<len(syms) else "?"; va=plt['addr']+0x20+0x10*i
    rows.append(f"rel[{i:03d}] PLT=0x{va:x} GOT=0x{ro:x} symbol={name}")
out=root/"analysis"/"native"/"plt_map_corrected.txt"
out.write_text("\n".join(rows)+"\n",encoding="utf-8")
print(f"OUTPUT={out}")
for row in rows:
    if any(x in row for x in ("PLT=0x65fc0","PLT=0x66020","PLT=0x66030","PLT=0x66040","PLT=0x66050","PLT=0x66060","PLT=0x66080","PLT=0x66090","PLT=0x660e0","PLT=0x660f0")):
        print(row)
