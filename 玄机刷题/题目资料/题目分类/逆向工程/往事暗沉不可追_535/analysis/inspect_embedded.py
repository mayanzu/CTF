from pathlib import Path
import marshal, sys, types
p=Path(sys.argv[1]); b=p.read_bytes()
print("file="+p.name.encode("ascii","backslashreplace").decode())
print(f"size={len(b)}")
print("first 64 bytes="+b[:64].hex(" "))
for skip in (0,8,12,16):
    try:
        obj=marshal.loads(b[skip:])
        print(f"marshal.loads(skip={skip}) => {type(obj).__name__}, consumed candidate bytes={len(b)-skip}")
        if isinstance(obj,types.CodeType):
            print(f"  name={obj.co_name!r} filename={obj.co_filename!r} names={obj.co_names!r}")
            print(f"  const count={len(obj.co_consts)}; first constants={obj.co_consts[:20]!r}")
    except Exception as e: print(f"marshal.loads(skip={skip}) failed: {type(e).__name__}: {e}")