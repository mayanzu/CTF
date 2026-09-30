import pathlib,struct,sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
b=pathlib.Path(sys.argv[1]).read_bytes(); u32=lambda o:struct.unpack_from('<I',b,o)[0]; i32=lambda o:struct.unpack_from('<i',b,o)[0]; u64=lambda o:struct.unpack_from('<Q',b,o)[0]
h=b.find(b'\xf1\xff\xff\xff\x00\x00\x01\x08'); n=u64(h+8); text=u64(h+24); fn=h+u64(h+32); pcln=h+u64(h+64); base=pcln
fs=[]
for i in range(n):
 ent=u32(base+8*i); fo=u32(base+8*i+4); no=i32(base+fo+4); name=b[fn+no:].split(b'\0',1)[0].decode('utf8','replace'); fs.append((ent,fo,name))
for idx,(ent,fo,name) in enumerate(fs):
 if name!='main.main':continue
 end=u32(base+8*n) if idx+1==n else fs[idx+1][0]; va=text+ent; size=end-ent; rva=va-0x400000; off=0x600+(rva-0x1000)
 print(f'{name}: VA=0x{va:x} RVA=0x{rva:x} size=0x{size:x} raw=0x{off:x} next_entry=0x{text+end:x}')
 md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
 for ins in md.disasm(b[off:off+size],va):
  print(f'{ins.address:016x}: {ins.bytes.hex():<24} {ins.mnemonic:<8} {ins.op_str}')
