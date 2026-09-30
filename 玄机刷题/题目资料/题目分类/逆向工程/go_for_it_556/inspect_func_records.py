import pathlib,struct
b=pathlib.Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\go_for_it_556\go.exe").read_bytes(); base=0x120e00
for off in (0x6278,0x62a8,0x6310,0x6378):
 p=base+off
 print(f"\nfuncoff={off:#x} filepos={p:#x}")
 for o in range(p,p+0x60,16):
  c=b[o:o+16]; print(f"{o:08x}: {c.hex(' ')}  {''.join(chr(x) if 32<=x<127 else '.' for x in c)}")
 print("ints",[hex(x) for x in struct.unpack_from("<16I",b,p)])
