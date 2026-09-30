from pathlib import Path
import hashlib

source = Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\PaluArray_546\PaluArray_flag.exe")
out = source.with_name("PaluArray_flag_upx_names.exe")
data = bytearray(source.read_bytes())
patches = {0x208: b"UPX0", 0x230: b"UPX1", 0x3E0: b"UPX!"}
for offset, replacement in patches.items():
    old = bytes(data[offset:offset+4])
    print(f"offset=0x{offset:x} old={old!r} new={replacement!r}")
    if old != b"PALU":
        raise SystemExit(f"unexpected bytes at 0x{offset:x}")
    data[offset:offset+4] = replacement
out.write_bytes(data)
print(f"patched={out} size={len(data)} sha256={hashlib.sha256(data).hexdigest()}")
