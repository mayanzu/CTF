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
    secs.append({"idx":i,"name":name,"type":s[1],"addr":s[3],"off":s[4],"size":s[5],"link":s[6],"info":s[7],"entsize":s[9]})
for s in secs:
    if s["name"] in (".plt",".plt.sec",".rela.plt",".rel.plt",".dynsym",".dynstr"):
        print(f"SECTION {s['name']} addr=0x{s['addr']:x} off=0x{s['off']:x} size=0x{s['size']:x} entsize={s['entsize']} link={s['link']}")
dynsym=next(s for s in secs if s["name"]==".dynsym"); dynstr=next(s for s in secs if s["name"]==".dynstr")
st=b[dynstr['off']:dynstr['off']+dynstr['size']]
syms=[]
for off in range(dynsym['off'],dynsym['off']+dynsym['size'],dynsym['entsize']):
    no,info,other,shndx,val,size=struct.unpack_from("<IBBHQQ",b,off)
    e=st.find(b"\0",no); name=st[no:e].decode("utf-8","replace") if no<len(st) else ""
    syms.append(name)
for relsec in [s for s in secs if s["name"] in (".rela.plt",".rel.plt")]:
    for i,off in enumerate(range(relsec['off'],relsec['off']+relsec['size'],relsec['entsize'])):
        if relsec['name']==".rela.plt": ro,info,add=struct.unpack_from("<QQq",b,off); idx=info>>32
        else: ro,info=struct.unpack_from("<QQ",b,off); idx=info>>32
        sym=syms[idx] if idx<len(syms) else "?"
        # common AArch64 PLT uses PLT[0] of 32 bytes and 16-byte per relocation.
        print(f"PLT_CANDIDATE {sym} rel_index={i} plt=0x{0x65f20+32+16*i:x} GOT=0x{ro:x} info=0x{info:x}")
