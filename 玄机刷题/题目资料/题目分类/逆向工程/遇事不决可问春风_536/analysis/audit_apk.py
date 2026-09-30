"""Read-only inventory and targeted string scan of an APK ZIP container."""
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path

path=Path(sys.argv[1])
pattern=re.compile(rb"(?i)flag\s*\{|reflag|flag_(?:prefix|suffix)|encrypted_parts|xor_key|checkpassword|decryptpassword|buildflag")
with zipfile.ZipFile(path) as z:
    infos=z.infolist()
    print(f"APK {path.name}: {len(infos)} entries, {path.stat().st_size} bytes")
    roots=Counter((i.filename.split("/",1)[0] if "/" in i.filename else "<root>") for i in infos)
    print("Top-level entry counts:")
    for name,count in sorted(roots.items()): print(f"  {name}: {count}")
    print("Potential nonstandard payload entries:")
    unusual=[]
    for i in infos:
        n=i.filename.lower()
        if n.startswith(("assets/","lib/","res/raw/")) or (".dex" not in n and "/" not in n and not n.startswith("meta-inf/")):
            unusual.append(i)
    if unusual:
        for i in unusual: print(f"  {i.filename} | {i.file_size} bytes")
    else: print("  none outside normal Android resources/signature metadata")
    print("Targeted flag/logic markers in APK entries:")
    found=0
    for info in infos:
        raw=z.read(info)
        for m in pattern.finditer(raw):
            lo=max(0,m.start()-24); hi=min(len(raw),m.end()+40)
            sample=raw[lo:hi].decode("utf-8","backslashreplace").replace("\x00",".")
            print(f"  {info.filename}: offset=0x{m.start():x} bytes={sample!r}")
            found+=1
    if not found: print("  no targeted marker found")
