from pathlib import Path
import struct, re, hashlib
root=Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\hookme_542")
libroot=root/"analysis"/"components"/"lib"
out=root/"analysis"/"native"
out.mkdir(parents=True,exist_ok=True)
def cstr(buf,off):
    if off>=len(buf): return ""
    end=buf.find(b"\0",off)
    if end<0: end=len(buf)
    return buf[off:end].decode("utf-8","replace")
for path in sorted(libroot.rglob("*.so")):
    b=path.read_bytes(); cls=b[4]; endian=b[5]
    if b[:4]!=b"\x7fELF" or endian!=1: print(f"SKIP bad ELF {path}"); continue
    if cls==2:
        typ,mach,ver,entry,phoff,shoff,flags,ehsize,phentsize,phnum,shentsize,shnum,shstr=struct.unpack_from("<HHIQQQIHHHHHH",b,16)
        sh_fmt="<IIQQQQIIQQ"; sh_n=64
        sym_fmt="<IBBHQQ"; sym_n=24
    else:
        typ,mach,ver,entry,phoff,shoff,flags,ehsize,phentsize,phnum,shentsize,shnum,shstr=struct.unpack_from("<HHIIIIIHHHHHH",b,16)
        sh_fmt="<IIIIIIIIII"; sh_n=40
        sym_fmt="<IIIBBH"; sym_n=16
    raw=[]
    for i in range(shnum): raw.append(struct.unpack_from(sh_fmt,b,shoff+i*shentsize))
    shstrdat=b[raw[shstr][4]:raw[shstr][4]+raw[shstr][5]] if shstr<shnum else b""
    secs=[]
    for i,s in enumerate(raw):
        name=cstr(shstrdat,s[0]); secs.append(dict(i=i,name=name,type=s[1],flags=s[2],addr=s[3],off=s[4],size=s[5],link=s[6],info=s[7],align=s[8],entsize=s[9]))
    syms=[]
    for sec in secs:
        if sec["type"] not in (2,11) or not sec["entsize"] or sec["link"]>=len(secs): continue
        strsec=secs[sec["link"]]; st=b[strsec["off"]:strsec["off"]+strsec["size"]]
        for off in range(sec["off"],sec["off"]+sec["size"],sec["entsize"]):
            if off+sym_n>len(b): break
            vals=struct.unpack_from(sym_fmt,b,off)
            if cls==2: no,info,other,shndx,val,size=vals
            else: no,val,size,info,other,shndx=vals
            name=cstr(st,no); syms.append((name,val,size,info,shndx,sec["name"]))
    arch={3:"x86",40:"arm",62:"x86_64",183:"aarch64"}.get(mach,str(mach))
    ascii_strings=[]
    for m in re.finditer(rb"[\x20-\x7e]{4,}",b):
        s=m.group().decode("ascii","ignore")
        if re.search(r"(?i)JNI|Java_|hook|flag|check|verify|secret|cipher|crypt|package|input|success|wrong|correct|sha|md5|rc4|key|native|name|system",s): ascii_strings.append((m.start(),s))
    report=[f"FILE={path}",f"SHA256={hashlib.sha256(b).hexdigest().upper()}",f"ELF_CLASS={32 if cls==1 else 64} MACHINE={mach} ARCH={arch} TYPE={typ} ENTRY=0x{entry:x}","SECTIONS:"]
    report += [f"{s['i']:3} {s['name']:<22} addr=0x{s['addr']:x} off=0x{s['off']:x} size=0x{s['size']:x} type={s['type']}" for s in secs if s['name'] in ('.text','.rodata','.dynsym','.symtab','.strtab','.dynstr','.init_array','.got','.got.plt','.rela.dyn','.rel.dyn')]
    report.append("EXPORTED/DEFINED FUNCTION SYMBOLS:")
    fs=[s for s in syms if (s[3]&15)==2 and s[4]!=0 and s[0]]
    report += [f"{name} value=0x{val:x} size=0x{size:x} shndx={shndx} table={table}" for name,val,size,info,shndx,table in fs]
    report.append("MATCHING ASCII STRINGS:")
    report += [f"0x{off:x}\t{s}" for off,s in ascii_strings]
    textpath=out/(path.parent.name+"_"+path.name+".txt")
    textpath.write_text("\n".join(report)+"\n",encoding="utf-8")
    print(f"{path.parent.name}/{path.name}: sha256={hashlib.sha256(b).hexdigest().upper()} arch={arch} sections={shnum} funcs={len(fs)} matched_strings={len(ascii_strings)} report={textpath}")
    for row in fs:
        if any(k in row[0] for k in ("JNI","Java_","RegisterNatives","init")): print(f"  JNI_SYMBOL={row[0]} value=0x{row[1]:x} size=0x{row[2]:x}")
    for off,s in ascii_strings[:40]: print(f"  STR@0x{off:x}={s}")
