from pathlib import Path
import struct, hashlib
root=Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\hookme_542")
for dex in sorted((root/"analysis"/"components").glob("classes*.dex")):
    b=dex.read_bytes()
    if b[:4]!=b"dex\n": continue
    def uleb(p):
        v=s=0
        while 1:
            x=b[p]; p+=1; v|=(x&127)<<s
            if x<128:return v,p
            s+=7
    def string_at(p):
        _,p=uleb(p); e=b.index(b"\0",p); return b[p:e].decode("utf-8","replace")
    sc,so=struct.unpack_from("<II",b,0x38); strings=[string_at(struct.unpack_from("<I",b,so+4*i)[0]) for i in range(sc)]
    tc,to=struct.unpack_from("<II",b,0x40); type_string=[struct.unpack_from("<I",b,to+4*i)[0] for i in range(tc)]; types=[strings[x] for x in type_string]
    pc,po=struct.unpack_from("<II",b,0x48); protos=[]
    for i in range(pc):
        shorty,ret,params=struct.unpack_from("<III",b,po+12*i)
        args=[]
        if params:
            size=struct.unpack_from("<I",b,params)[0]
            args=[types[struct.unpack_from("<H",b,params+4+2*j)[0]] for j in range(size)]
        protos.append("("+"".join(args)+")"+types[ret])
    fc,fo=struct.unpack_from("<II",b,0x50); fields=[]
    for i in range(fc):
        c,t,n=struct.unpack_from("<HHI",b,fo+8*i); fields.append((types[c],types[t],strings[n]))
    mc,mo=struct.unpack_from("<II",b,0x58); methods=[]
    for i in range(mc):
        c,p,n=struct.unpack_from("<HHI",b,mo+8*i); methods.append((types[c],protos[p],strings[n]))
    cc,co=struct.unpack_from("<II",b,0x60); lines=[f"===== {dex.name} sha256={hashlib.sha256(b).hexdigest().upper()} class_defs={cc} ====="]
    opnames={0x00:"nop",0x01:"move",0x02:"move/from16",0x03:"move/16",0x04:"move-wide",0x05:"move-wide/from16",0x06:"move-wide/16",0x07:"move-object",0x08:"move-object/from16",0x09:"move-object/16",0x0a:"move-result",0x0b:"move-result-wide",0x0c:"move-result-object",0x0d:"move-exception",0x0e:"return-void",0x0f:"return",0x10:"return-wide",0x11:"return-object",0x12:"const/4",0x13:"const/16",0x14:"const",0x15:"const/high16",0x16:"const-wide/16",0x17:"const-wide/32",0x18:"const-wide",0x19:"const-wide/high16",0x1a:"const-string",0x1b:"const-string/jumbo",0x1c:"const-class",0x1d:"monitor-enter",0x1e:"monitor-exit",0x1f:"check-cast",0x20:"instance-of",0x21:"array-length",0x22:"new-instance",0x23:"new-array",0x24:"filled-new-array",0x25:"filled-new-array/range",0x26:"fill-array-data",0x27:"throw",0x28:"goto",0x29:"goto/16",0x2a:"goto/32",0x2b:"packed-switch",0x2c:"sparse-switch",0x2d:"cmpl-float",0x2e:"cmpg-float",0x2f:"cmpl-double",0x30:"cmpg-double",0x31:"cmp-long",0x32:"if-eq",0x33:"if-ne",0x34:"if-lt",0x35:"if-ge",0x36:"if-gt",0x37:"if-le",0x38:"if-eqz",0x39:"if-nez",0x3a:"if-ltz",0x3b:"if-gez",0x3c:"if-gtz",0x3d:"if-lez",0x44:"aget",0x45:"aget-wide",0x46:"aget-object",0x47:"aget-boolean",0x48:"aget-byte",0x49:"aget-char",0x4a:"aget-short",0x4b:"aput",0x4c:"aput-wide",0x4d:"aput-object",0x4e:"aput-boolean",0x4f:"aput-byte",0x50:"aput-char",0x51:"aput-short",0x52:"iget",0x53:"iget-wide",0x54:"iget-object",0x55:"iget-boolean",0x56:"iget-byte",0x57:"iget-char",0x58:"iget-short",0x59:"iput",0x5a:"iput-wide",0x5b:"iput-object",0x60:"sget",0x61:"sget-wide",0x62:"sget-object",0x63:"sget-boolean",0x64:"sget-byte",0x65:"sget-char",0x66:"sget-short",0x67:"sput",0x68:"sput-wide",0x69:"sput-object",0x6a:"sput-boolean",0x6b:"sput-byte",0x6c:"sput-char",0x6d:"sput-short",0x6e:"invoke-virtual",0x6f:"invoke-super",0x70:"invoke-direct",0x71:"invoke-static",0x72:"invoke-interface",0x74:"invoke-virtual/range",0x75:"invoke-super/range",0x76:"invoke-direct/range",0x77:"invoke-static/range",0x78:"invoke-interface/range",0x7b:"neg-int",0x7c:"not-int",0x7d:"neg-long",0x7e:"not-long",0x7f:"neg-float",0x80:"neg-double",0x81:"int-to-long",0x82:"int-to-float",0x83:"int-to-double",0x84:"long-to-int",0x85:"long-to-float",0x86:"long-to-double",0x87:"float-to-int",0x88:"float-to-long",0x89:"float-to-double",0x8a:"double-to-int",0x8b:"double-to-long",0x8c:"double-to-float",0x8d:"int-to-byte",0x8e:"int-to-char",0x8f:"int-to-short",0xfa:"invoke-polymorphic",0xfb:"invoke-polymorphic/range",0xfc:"invoke-custom",0xfd:"invoke-custom/range",0xfe:"const-method-handle",0xff:"const-method-type"}
    def insn_len(op):
        if op in (0x02,0x05,0x08,0x13,0x15,0x16,0x1a,0x1c,0x1f,0x20,0x22,0x23,0x29,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x7b,0x7c,0x7d,0x7e,0x7f,0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f): return 1 if op>=0x7b and op<=0x8f else 2
        if op in (0x03,0x06,0x09,0x14,0x17,0x1b,0x24,0x25,0x26,0x2a,0x2b,0x2c,0x6e,0x6f,0x70,0x71,0x72,0x74,0x75,0x76,0x77,0x78,0xfa,0xfb,0xfc,0xfd): return 3 if op not in (0xfa,0xfb) else 4
        if op==0x18:return 5
        if op in (0x04,0x07,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x1d,0x1e,0x21,0x27,0x28,0x7b,0x7c,0x7d,0x7e,0x7f,0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f): return 1
        if op in range(0x90,0xe3): return 2 if op<0xb0 or op>=0xd0 else 1
        return 1
    for i in range(cc):
        class_idx,access,sup,if_off,src,ann,cd,sv=struct.unpack_from("<IIIIIIII",b,co+32*i); desc=types[class_idx]
        if not desc.startswith("Lcom/example/hookme/"): continue
        lines.append(f"\nCLASS {desc} access=0x{access:x} source={strings[src] if src!=0xffffffff and src<len(strings) else '-'}")
        if not cd: continue
        p=cd; sf,p=uleb(p); inf,p=uleb(p); direct,p=uleb(p); virt,p=uleb(p)
        for n in (sf,inf):
            idx=0
            for _ in range(n): idxd,p=uleb(p); flags,p=uleb(p); idx+=idxd
        for group,n in (("direct",direct),("virtual",virt)):
            idx=0
            for _ in range(n):
                d,p=uleb(p); flags,p=uleb(p); code,p=uleb(p); idx+=d
                cls,proto,name=methods[idx]
                lines.append(f"\nMETHOD {group} {name}{proto} access=0x{flags:x} code_off=0x{code:x}")
                if not code: continue
                regs,ins,outs,tries,dbg,sz=struct.unpack_from("<HHHHII",b,code)
                u=list(struct.unpack_from("<"+"H"*sz,b,code+16))
                lines.append(f"  registers={regs} ins={ins} outs={outs} tries={tries} insns={sz}")
                pc=0
                while pc<len(u):
                    w=u[pc]; op=w&255; ln=insn_len(op)
                    if ln<1 or pc+ln>len(u): ln=1
                    nameop=opnames.get(op,f"op_{op:02x}")
                    extra=""
                    if op==0x1a and pc+1<len(u): extra=f' string@{u[pc+1]}={strings[u[pc+1]]!r}'
                    elif op==0x1b and pc+2<len(u):
                        ix=u[pc+1]|(u[pc+2]<<16); extra=f' string@{ix}={strings[ix]!r}'
                    elif op in (0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d) and pc+1<len(u):
                        ix=u[pc+1]; extra=f' field@{ix}={fields[ix] if ix<len(fields) else "?"}'
                    elif op in tuple(range(0x6e,0x73))+tuple(range(0x74,0x79)) and pc+1<len(u):
                        ix=u[pc+1]; extra=f' method@{ix}={methods[ix] if ix<len(methods) else "?"}'
                    elif op in (0x13,0x16,0x29): extra=f' literal/signed={struct.unpack("<h",struct.pack("<H",u[pc+1]))[0]}' if pc+1<len(u) else ""
                    elif op==0x12: extra=f' literal={(w>>12)&15 if (w>>12)<8 else ((w>>12)&15)-16}'
                    elif op==0x14 and pc+2<len(u): extra=f' literal=0x{u[pc+1]|u[pc+2]<<16:08x}'
                    elif op in (0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x28):
                        delta=((w>>8)&255); delta=delta-256 if delta&128 else delta
                        extra+=f' branch_delta={delta} target={pc+delta}'
                    lines.append(f"  {pc:04x}: {nameop:<24} {w:04x} {u[pc+1:pc+ln]}{extra}")
                    pc+=ln
    path=root/"analysis"/"dex"/(dex.name+".disasm.txt")
    path.write_text("\n".join(lines)+"\n",encoding="utf-8")
    print(f"{dex.name}: app disassembly lines={len(lines)} path={path}")
