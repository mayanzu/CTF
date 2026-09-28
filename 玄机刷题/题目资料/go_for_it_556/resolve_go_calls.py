import pathlib,struct
b=pathlib.Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\go_for_it_556\go.exe").read_bytes(); hdr=0xe2460
nfunc,nfiles,fno,cu,ft,pct,pln=struct.unpack_from("<7Q",b,hdr+8); nb=hdr+fno; pb=hdr+pln
funcs=[]
for i in range(nfunc):
 entry,fo=struct.unpack_from("<QQ",b,pb+i*16); no=struct.unpack_from("<i",b,pb+fo+8)[0]
 end=b.find(b"\0",nb+no); name=b[nb+no:end].decode("utf-8","replace") if end>=0 else "?"
 funcs.append((entry,fo,name))
def resolve(pc):
 eligible=[i for i,x in enumerate(funcs) if x[0]<=pc]
 if not eligible:return None,None
 i=eligible[-1]; return funcs[i],(funcs[i+1][0] if i+1<len(funcs) else None)
print("CALL TARGETS")
for pc in [0x402180,0x448ba0,0x499600,0x494480,0x49e740,0x49e8a0,0x40c180,0x409920,0x47ec40,0x4329c0]:
 f,end=resolve(pc); endstr=(f"{end:#x}" if end is not None else "None")
 print(f"{pc:#x} -> {f[2] if f else None} entry={f[0]:#x} end={endstr} offset={pc-f[0]:#x}")
print("\nPCLNTAB FUNCTIONS NEAR main.main")
for entry,fo,name in funcs[-20:]:print(f"{entry:#x} {name}")
print("\nDATA AT MAIN LEA TARGETS")
for va in [0x4a8720,0x4ba5ec,0x4de9a0,0x4de9c0,0x4de248,0x4b06e0,0x4e00f0,0x5bbad8,0x4a80e0]:
 off=0x9e800+(va-0x4a0000) if 0x4a0000<=va<0x54e000 else None
 if off is None: print(f"{va:#x}: outside .rdata");continue
 chunk=b[off:off+80]; end=chunk.find(b"\0"); text=chunk[:end] if end>=0 else chunk
 print(f"{va:#x} file={off:#x} bytes={chunk[:40].hex(' ')} ascii={text!r}")
