import base64, pathlib, re
p = pathlib.Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\OpenHarmony_easyre_560\hap_extracted\ets\modules.abc")
b = p.read_bytes()
for start, end in [(0x1750,0x18a0),(0x20c0,0x2160),(0x2310,0x2540),(0x2550,0x2780)]:
    print(f"\nRAW {start:#x}..{end:#x}")
    for off in range(start, min(end,len(b)), 16):
        chunk = b[off:min(off+16,end,len(b))]
        hx = " ".join(f"{x:02x}" for x in chunk)
        asc = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        print(f"{off:06x}  {hx:<47} {asc}")
for token in [b"NzAyZDBlODgxZDNjNzNjOWIzOTBkZjIwNTRiZGQxNWNjY2I", b"#`d^ba_^YZZZVWXRRT"]:
    print(f"\nTOKEN {token!r}")
    try:
        decoded = base64.urlsafe_b64decode(token + b"="*((-len(token))%4))
        print(f"base64url={decoded!r} hex={decoded.hex()}")
    except Exception as e: print(f"decode error {e!r}")
    print(f"reverse={token[::-1]!r}")
