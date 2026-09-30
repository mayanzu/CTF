import struct
path=r"C:\Windows\System32\KERNELBASE.dll"
target=0x77724
data=open(path,"rb").read()
e_lfanew=struct.unpack_from("<I",data,0x3c)[0]
assert data[e_lfanew:e_lfanew+4]==b"PE\0\0"
coff=e_lfanew+4
nsec=struct.unpack_from("<H",data,coff+2)[0]
optsz=struct.unpack_from("<H",data,coff+16)[0]
opt=coff+20
magic=struct.unpack_from("<H",data,opt)[0]
assert magic==0x20b
export_rva,export_size=struct.unpack_from("<II",data,opt+112)
sectab=opt+optsz
sections=[]
for i in range(nsec):
    off=sectab+40*i
    name=data[off:off+8].split(b"\0")[0].decode("ascii","replace")
    vsize,va,rawsize,raw=struct.unpack_from("<IIII",data,off+8)
    sections.append((name,va,max(vsize,rawsize),raw,vsize,rawsize))
def rvaoff(rva):
    for name,va,size,raw,vsize,rawsize in sections:
        if va<=rva<va+size:
            return raw+(rva-va)
    raise ValueError(hex(rva))
print("path:",path,"size:",len(data),"imagebase:",hex(struct.unpack_from("<Q",data,opt+24)[0]))
print("export_rva_size:",hex(export_rva),hex(export_size),"target_rva:",hex(target))
print("sections:",sections)
off=rvaoff(export_rva)
fields=struct.unpack_from("<IIHHIIIIIII",data,off)
(_,_,_,_,name_rva,base,nfunc,nnames,func_rva,names_rva,ords_rva)=fields
print("export_dir:","base",base,"functions",nfunc,"names",nnames)
funcs=struct.unpack_from("<"+"I"*nfunc,data,rvaoff(func_rva))
names=struct.unpack_from("<"+"I"*nnames,data,rvaoff(names_rva))
ords=struct.unpack_from("<"+"H"*nnames,data,rvaoff(ords_rva))
byfunc={}
for nr,oi in zip(names,ords):
    end=data.find(b"\0",rvaoff(nr))
    nm=data[rvaoff(nr):end].decode("ascii","replace")
    fr=funcs[oi]
    byfunc.setdefault(fr,[]).append(nm)
near=sorted((rva,nms) for rva,nms in byfunc.items() if rva<=target)[-12:]
for rva,nms in near: print("export",hex(rva),",".join(nms))
print("next exports:")
for rva,nms in sorted((rva,nms) for rva,nms in byfunc.items() if rva>target)[:5]: print("export",hex(rva),",".join(nms))
