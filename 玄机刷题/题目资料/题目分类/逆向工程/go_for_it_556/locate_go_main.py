import pathlib,struct
b=pathlib.Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\go_for_it_556\go.exe").read_bytes()
hdr=0xe2460
nfunc,nfiles,funcname_off,cu_off,filetab_off,pctab_off,pcln_off=struct.unpack_from("<7Q",b,hdr+8)
name_base=hdr+funcname_off; pcln_base=hdr+pcln_off
print(f"nfunc={nfunc} names_base={name_base:#x} func_names_end={hdr+cu_off:#x} pcln_base={pcln_base:#x}")
def name_at(no):
    if no<0 or name_base+no>=len(b): return b"?"
    end=b.find(b"\0",name_base+no)
    return b"?" if end<0 else b[name_base+no:end]
for i in range(12):
    entry,fo=struct.unpack_from("<QQ",b,pcln_base+i*16)
    no=struct.unpack_from("<i",b,pcln_base+fo+8)[0]
    print(f"{i:4} entry={entry:#x} funcoff={fo:#x} nameoff={no:#x} name={name_at(no)!r}")
print("main-related functions:")
for i in range(nfunc):
    entry,fo=struct.unpack_from("<QQ",b,pcln_base+i*16)
    no=struct.unpack_from("<i",b,pcln_base+fo+8)[0]
    name=name_at(no)
    if b"main." in name:
        nxt=struct.unpack_from("<Q",b,pcln_base+(i+1)*16)[0] if i+1<nfunc else None
        print(f" index={i} entry={entry:#x} next={nxt!r} size={(nxt-entry if nxt else None)!r} funcoff={fo:#x} nameoff={no:#x} name={name!r}")
