import pathlib,struct
b=pathlib.Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\go_for_it_556\go.exe").read_bytes()
for start in (0xe2460,0xe24a0,0xee400,0x120e00):
 print(f"\nOFFSET {start:#x}")
 for o in range(start,start+0x80,16):
  c=b[o:o+16]; print(f"{o:08x}: {c.hex(' ')}  {''.join(chr(x) if 32<=x<127 else '.' for x in c)}")
