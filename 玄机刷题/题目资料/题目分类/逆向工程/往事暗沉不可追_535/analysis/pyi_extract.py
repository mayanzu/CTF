from pathlib import Path
import hashlib, struct, sys, zlib

src=Path(sys.argv[1]); out=Path(sys.argv[2]); data=src.read_bytes()
magic=b"MEI\x0c\x0b\x0a\x0b\x0e"
cookie_fmt="!8sIIII64s"
cookie_size=struct.calcsize(cookie_fmt)
hits=[]; start=0
while True:
    at=data.find(magic,start)
    if at<0: break
    hits.append(at); start=at+1
if not hits: raise SystemExit("PyInstaller CArchive cookie magic not found")
cookie_at=hits[-1]
if cookie_at+cookie_size>len(data): raise SystemExit("Truncated CArchive cookie")
m,pkglen,tocoff,toclen,pyver,pylib=struct.unpack_from(cookie_fmt,data,cookie_at)
archive_start=len(data)-pkglen
toc_start=archive_start+tocoff
if archive_start<0 or toc_start<archive_start or toc_start+toclen>cookie_at:
    raise SystemExit(f"Invalid CArchive bounds: start={archive_start}, toc={toc_start}, len={toclen}, cookie={cookie_at}")
entries=[]
pos=toc_start; end=toc_start+toclen
header_fmt="!iIIIBc"; header_size=struct.calcsize(header_fmt)
while pos<end:
    if pos+header_size>end: raise SystemExit(f"Truncated TOC header at {pos:#x}")
    entrylen,off,clen,ulen,flag,tcode=struct.unpack_from(header_fmt,data,pos)
    if entrylen<header_size+1 or pos+entrylen>end: raise SystemExit(f"Invalid TOC entry length {entrylen} at {pos:#x}")
    nraw=data[pos+header_size:pos+entrylen].split(b"\0",1)[0]
    name=nraw.decode("utf-8","replace")
    entries.append((name,off,clen,ulen,flag,tcode.decode("ascii","replace")))
    pos+=entrylen
if pos!=end: raise SystemExit(f"TOC parse ended at {pos:#x}, expected {end:#x}")
out.mkdir(parents=True,exist_ok=True)
rows=[]
for i,(name,off,clen,ulen,flag,typ) in enumerate(entries):
    bstart=archive_start+off; bend=bstart+clen
    if bstart<archive_start or bend>cookie_at: raise SystemExit(f"Entry outside archive: {name!r}")
    payload=data[bstart:bend]
    status="ok"
    if flag:
        try: payload=zlib.decompress(payload)
        except Exception as e: status=f"zlib-error:{type(e).__name__}:{e}"
    if status=="ok" and len(payload)!=ulen: status=f"length-mismatch:{len(payload)}!={ulen}"
    cleaned=name.replace("//","/").replace("/","_")
    while ".." in cleaned: cleaned=cleaned.replace("..","_")
    cleaned="".join(c if c.isalnum() or c in "._- " else "_" for c in cleaned).strip(" .") or "unnamed"
    dest=out/f"{i:04d}_{cleaned}"
    if status=="ok": dest.write_bytes(payload)
    rows.append((i,name,typ,flag,off,clen,ulen,status,dest.name if status=="ok" else "",hashlib.sha256(payload).hexdigest() if status=="ok" else ""))
report=[]
report.append(f"Cookie magic hits: {[hex(x) for x in hits]}")
report.append(f"Cookie offset: {cookie_at:#x}; size={cookie_size}; archive start={archive_start:#x}; package length={pkglen}")
report.append(f"TOC offset(relative)={tocoff:#x}, length={toclen:#x}, absolute={toc_start:#x}; Python version field={pyver}")
report.append(f"Python library field: {pylib.split(bytes([0]),1)[0].decode('ascii','replace')}")
report.append(f"TOC entries: {len(entries)}")
report.append("index | type | compressed | offset | stored | unpacked | status | name | extracted | sha256")
for i,name,typ,flag,off,clen,ulen,status,dest,hsh in rows:
    report.append(f"{i:04d} | {typ} | {flag} | {off:#x} | {clen} | {ulen} | {status} | {name} | {dest} | {hsh}")
(out/"pyinstaller_toc.txt").write_text("\n".join(report)+"\n",encoding="utf-8")
print("\n".join(report[:5]))
print(f"Inventory written: pyinstaller_toc.txt; extracted entries: {sum(r[7]=='ok' for r in rows)}/{len(rows)}")
for i,name,typ,flag,off,clen,ulen,status,dest,hsh in rows:
    safe=name.encode("ascii","backslashreplace").decode("ascii")
    print(f"  {i:04d} {typ} compressed={flag} {clen}->{ulen} {status} {safe}")