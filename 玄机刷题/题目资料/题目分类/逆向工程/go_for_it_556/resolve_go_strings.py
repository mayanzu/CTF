import pathlib,struct
b=pathlib.Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\go_for_it_556\go.exe").read_bytes()
def fileoff(va):
 if 0x4a0000<=va<0x54e000: return 0x9e800+(va-0x4a0000)
 if 0x54e000<=va<0x5c2000: return 0x14be00+(va-0x54e000)
 return None
for va in [0x4de248,0x4de258,0x4ba5ec,0x4a8720,0x4b06e0]:
 off=fileoff(va)
 if off is None:print(f"{va:#x} outside mapped sections");continue
 print(f"\nVA={va:#x} file={off:#x}")
 for i in range(0,0x40,16):
  p=off+i; c=b[p:p+16]; print(f" {p:#x}: {c.hex(' ')} {''.join(chr(x) if 32<=x<127 else '.' for x in c)}")
 for i in range(0,0x30,16):
  ptr,n=struct.unpack_from("<QQ",b,off+i)
  target=fileoff(ptr)
  if target is not None and n<128:
   print(f" string-header[{i//16}] ptr={ptr:#x} len={n} file={target:#x} bytes={b[target:target+n]!r}")
print("\nSTRING HIT AROUND ASCII success in .rdata")
pos=b.find(b"success")
print(f"offset={pos:#x} bytes={b[pos-16:pos+32]!r}")
