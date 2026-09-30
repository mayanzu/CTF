from pathlib import Path
p=Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\PaluFlat_547\analysis\extracted\PaluFlat.exe")
size=p.stat().st_size
chunk_size=16*1024*1024
nonzero=0; chunks=0; first=None; last=None
with p.open("rb") as f:
    f.seek(0x4800); off=0x4800
    while True:
        b=f.read(chunk_size)
        if not b: break
        chunks+=1
        n=len(b)-b.count(0)
        nonzero+=n
        if n:
            t=b.strip(b"\0")
            if first is None: first=off+b.find(t[:1])
            last=off+b.rfind(t[-1:])
        off+=len(b)
print("source size:",size)
print("overlay start:",hex(0x4800))
print("overlay size:",size-0x4800)
print("chunk size:",chunk_size)
print("chunks scanned:",chunks)
print("nonzero overlay byte count:",nonzero)
print("first/last nonzero:",first,last)
assert nonzero==0
