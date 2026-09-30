import hashlib, pathlib, re
p=pathlib.Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\go_for_it_556\go.exe")
b=p.read_bytes()
print(f"size={len(b)} SHA256={hashlib.sha256(b).hexdigest()}")
seen=set()
for m in re.finditer(rb"[\x20-\x7e]{4,}",b):
    s=m.group().decode("ascii","replace")
    low=s.lower()
    relevant=(s.startswith(("main.","go.","github.com/","golang.org/")) or any(k in low for k in ["flag{","correct","wrong","incorrect","success","failed","enter","input","password","secret","answer","try again","go_for_it","for it","congrat","try your","what is","please","key="]))
    if relevant and len(s)<=240 and s not in seen:
        seen.add(s); print(f"0x{m.start():08x} len={len(s):3} {s}")
