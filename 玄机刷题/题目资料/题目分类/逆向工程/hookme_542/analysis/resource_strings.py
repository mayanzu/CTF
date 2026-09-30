from pathlib import Path
from zipfile import ZipFile
import re, hashlib
root=Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\hookme_542")
apk=root/"附件解包"/"hookme"/"HookMe.apk"
out=root/"analysis"/"resources"
out.mkdir(parents=True,exist_ok=True)
with ZipFile(apk) as zf:
    names=[n for n in zf.namelist() if n=="resources.arsc" or n=="AndroidManifest.xml" or n.startswith("res/") and n.endswith(".xml")]
    report=[]
    for name in names:
        data=zf.read(name)
        ascii_strings=[(m.start(),m.group().decode("ascii","ignore")) for m in re.finditer(rb"[\x20-\x7e]{4,}",data)]
        utf16=[]
        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}",data):
            utf16.append((m.start(),m.group().decode("utf-16le","ignore")))
        rows=[(o,s,"ASCII") for o,s in ascii_strings]+[(o,s,"UTF16LE") for o,s in utf16]
        report.append(f"\n===== {name} bytes={len(data)} sha256={hashlib.sha256(data).hexdigest().upper()} =====")
        for off,s,enc in sorted(rows):
            report.append(f"0x{off:x}\t{enc}\t{s}")
        dest=out/Path(name).name
        dest.write_bytes(data)
    txt=out/"compiled_resource_strings.txt"
    txt.write_text("\n".join(report)+"\n",encoding="utf-8")
    print(f"RESOURCES_SCANNED={len(names)} STRINGS={sum(1 for x in report if x and not x.startswith('=====') and not x.startswith('0x'))} OUTPUT={txt}")
    for row in report:
        if any(k in row.lower() for k in ("cipher","flag","secret","hookme","example","success","wrong","[0-9a-f]{32}")):
            print(row.encode("ascii","backslashreplace").decode("ascii"))
