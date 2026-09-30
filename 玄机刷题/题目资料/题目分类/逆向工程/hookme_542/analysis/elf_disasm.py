from pathlib import Path
import struct, hashlib
from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_ARM, CS_ARCH_X86, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_64, CS_MODE_32
root=Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\hookme_542")
for path in sorted((root/"analysis"/"components"/"lib").rglob("*.so")):
    b=path.read_bytes(); cls=b[4]; mach=struct.unpack_from("<H",b,18)[0]
    if cls==2:
        fields=struct.unpack_from("<HHIQQQIHHHHHH",b,16); shoff=fields[5]; shentsize=fields[10]; shnum=fields[11]; shstr=fields[12]; sh_fmt="<IIQQQQIIQQ"; sym_fmt="<IBBHQQ"; sym_size=24
    else:
        fields=struct.unpack_from("<HHIIIIIHHHHHH",b,16); shoff=fields[5]; shentsize=fields[10]; shnum=fields[11]; shstr=fields[12]; sh_fmt="<IIIIIIIIII"; sym_fmt="<IIIBBH"; sym_size=16
    raw=[struct.unpack_from(sh_fmt,b,shoff+i*shentsize) for i in range(shnum)]
    shname=b[raw[shstr][4]:raw[shstr][4]+raw[shstr][5]]
    secs=[]
    for s in raw:
        end=shname.find(b"\0",s[0]); name=shname[s[0]:end].decode("ascii","replace")
        secs.append({"name":name,"type":s[1],"addr":s[3],"off":s[4],"size":s[5],"link":s[6],"entsize":s[9]})
    symbols=[]
    for sec in secs:
        if sec["type"] not in (2,11) or not sec["entsize"]: continue
        stsec=secs[sec["link"]]; strings=b[stsec["off"]:stsec["off"]+stsec["size"]]
        for off in range(sec["off"],sec["off"]+sec["size"],sec["entsize"]):
            vals=struct.unpack_from(sym_fmt,b,off)
            if cls==2: no,info,other,shndx,val,size=vals
            else: no,val,size,info,other,shndx=vals
            e=strings.find(b"\0",no); name=strings[no:e].decode("utf-8","replace") if no<len(strings) else ""
            if name and shndx: symbols.append((name,val,size,info,shndx))
    if mach==183: arch,mode=CS_ARCH_ARM64,0
    elif mach==40: arch,mode=CS_ARCH_ARM,(CS_MODE_THUMB if struct.unpack_from("<H",b,18)[0]==40 and False else CS_MODE_ARM)
    elif mach==62: arch,mode=CS_ARCH_X86,CS_MODE_64
    elif mach==3: arch,mode=CS_ARCH_X86,CS_MODE_32
    else: continue
    md=Cs(arch,mode); md.detail=True
    targets=[s for s in symbols if any(k in s[0] for k in ("initializeSBox","_Z3ksa","_Z4prga","rc4Encrypt","Java_com_example_hookme_MainActivity_setPackageNameToNative","Java_com_example_hookme_MainActivity_rc4Encrypt"))]
    lines=[f"FILE={path}",f"SHA256={hashlib.sha256(b).hexdigest().upper()}",f"MACHINE={mach} target_symbols={len(targets)}"]
    for name,va,size,info,shndx in targets:
        if not size: continue
        sec=next((x for x in secs if x["addr"]<=va<x["addr"]+x["size"]),None)
        if not sec: continue
        off=sec["off"]+(va-sec["addr"]); code=b[off:off+size]
        lines.append(f"\n===== {name} VA=0x{va:x} FILEOFF=0x{off:x} SIZE=0x{size:x} =====")
        ins=list(md.disasm(code,va|1 if mach==40 and va&1 else va))
        lines += [f"{i.address:08x}: {i.mnemonic:<10} {i.op_str}" for i in ins]
    out=root/"analysis"/"native"/(path.parent.name+"_"+path.name+".disasm.txt")
    out.write_text("\n".join(lines)+"\n",encoding="utf-8")
    print(f"{path.parent.name}/{path.name}: disassembled {len(targets)} target symbols; output={out}")
