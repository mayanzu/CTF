from pathlib import Path
from zipfile import ZipFile
import struct,hashlib
root=Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\hookme_542")
apk=root/"附件解包"/"hookme"/"HookMe.apk"
def pool(b,o):
    typ,hs,size=struct.unpack_from("<HHI",b,o)
    if typ!=1: raise ValueError(f"not string pool at {o:x}: {typ:x}")
    n,styles,flags,strings_start,styles_start=struct.unpack_from("<IIIII",b,o+8)
    utf8=bool(flags&0x100)
    offsets=[struct.unpack_from("<I",b,o+hs+4*i)[0] for i in range(n)]
    def u8len(p):
        a=b[p]; p+=1
        if a&0x80: q=b[p];p+=1;return ((a&0x7f)<<8)|q,p
        return a,p
    out=[]
    for rel in offsets:
        p=o+strings_start+rel
        if utf8:
            _,p=u8len(p); nb,p=u8len(p); raw=b[p:p+nb]; s=raw.decode("utf-8","replace")
        else:
            n16,p=struct.unpack_from("<H",b,p)[0],p+2
            if n16&0x8000:
                n16=((n16&0x7fff)<<16)|struct.unpack_from("<H",b,p)[0];p+=2
            s=b[p:p+2*n16].decode("utf-16le","replace")
        out.append(s)
    return out,size,hs
with ZipFile(apk) as zf: b=zf.read("resources.arsc")
report=[f"ARSC bytes={len(b)} sha256={hashlib.sha256(b).hexdigest().upper()}"]
typ,hs,sz=struct.unpack_from("<HHI",b,0)
report.append(f"TABLE type=0x{typ:04x} header_size=0x{hs:x} size=0x{sz:x} package_count={struct.unpack_from('<I',b,8)[0]}")
p=hs; global_pool=[]; packages=[]
while p<sz:
    ct,ch,cs=struct.unpack_from("<HHI",b,p)
    report.append(f"CHUNK off=0x{p:x} type=0x{ct:04x} header=0x{ch:x} size=0x{cs:x}")
    if ct==1:
        global_pool,_,_=pool(b,p)
        report.append(f"GLOBAL_STRING_POOL count={len(global_pool)}")
    elif ct==0x200:
        pid=struct.unpack_from("<I",b,p+8)[0]
        pname=b[p+12:p+12+256].decode("utf-16le","ignore").split("\0",1)[0]
        typeoff=struct.unpack_from("<I",b,p+268)[0]; keyoff=struct.unpack_from("<I",b,p+276)[0]
        pk={"off":p,"size":cs,"header":ch,"id":pid,"name":pname,"typeoff":typeoff,"keyoff":keyoff}
        to=p+typeoff; ko=p+keyoff
        pk["types"]=pool(b,to)[0]; pk["keys"]=pool(b,ko)[0]
        if ch>=0x120: pk["typeidoff"]=struct.unpack_from("<I",b,p+284)[0]
        else: pk["typeidoff"]=0
        packages.append(pk)
        report.append(f"PACKAGE id={pid} name={pname} header=0x{ch:x} type_pool={len(pk['types'])} key_pool={len(pk['keys'])} typeIdOffset={pk['typeidoff']}")
    p+=cs
for pk in packages:
    p=pk["off"]+pk["header"]; end=pk["off"]+pk["size"]
    while p<end:
        ct,ch,cs=struct.unpack_from("<HHI",b,p)
        if ct==0x201:
            tid,flags,reserved,entries,entries_start=struct.unpack_from("<BBHII",b,p+8)
            type_name=pk["types"][tid-1] if tid and tid-1<len(pk["types"]) else f"type{tid}"
            offs=[struct.unpack_from("<I",b,p+ch+4*i)[0] for i in range(entries)]
            for idx,rel in enumerate(offs):
                if rel==0xffffffff: continue
                e=p+entries_start+rel
                esize,eflags,key=struct.unpack_from("<HHI",b,e)
                keyname=pk["keys"][key] if key<len(pk["keys"]) else f"key{key}"
                if eflags&1:
                    value=f"complex flags=0x{eflags:x}"
                else:
                    vsize,vres,vtype,vdata=struct.unpack_from("<HBBI",b,e+esize)
                    if vtype==3 and vdata<len(global_pool): value=repr(global_pool[vdata])
                    else: value=f"type=0x{vtype:02x} data=0x{vdata:x}"
                rid=(pk["id"]<<24)|((tid+pk["typeidoff"])<<16)|idx
                if keyname=="correct_ciphertext" or "hookme" in keyname.lower() or "flag" in keyname.lower():
                    report.append(f"RESOURCE 0x{rid:08x} {type_name}/{keyname} = {value}")
        p+=cs
out=root/"analysis"/"resources"/"arsc_parse.txt"
out.write_text("\n".join(report)+"\n",encoding="utf-8")
print(f"OUTPUT={out}")
for row in report:
    if "correct_ciphertext" in row or row.startswith("PACKAGE") or row.startswith("TABLE") or row.startswith("GLOBAL_STRING_POOL"):
        print(row.encode("ascii","backslashreplace").decode("ascii"))
