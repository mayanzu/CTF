from pathlib import Path
import struct, hashlib
root=Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\hookme_542")
for dex in sorted((root/"analysis"/"components").glob("classes*.dex")):
 b=dex.read_bytes()
 if b[:4]!=b"dex\n": continue
 def u(p):
  v=s=0
  while True:
   x=b[p];p+=1;v|=(x&127)<<s
   if x<128:return v,p
   s+=7
 sc,so=struct.unpack_from("<II",b,0x38); strings=[]
 for i in range(sc):
  p=struct.unpack_from("<I",b,so+4*i)[0];_,p=u(p);e=b.index(b"\0",p);strings.append(b[p:e].decode("utf-8","replace"))
 tc,to=struct.unpack_from("<II",b,0x40); tid=[struct.unpack_from("<I",b,to+4*i)[0] for i in range(tc)];types=[strings[x] for x in tid]
 mc,mo=struct.unpack_from("<II",b,0x58); methods=[]
 for i in range(mc): c,pr,n=struct.unpack_from("<HHI",b,mo+8*i);methods.append((types[c],strings[n]))
 cc,co=struct.unpack_from("<II",b,0x60); rows=[f"DEX={dex.name} SHA256={hashlib.sha256(b).hexdigest().upper()} class_defs={cc} methods={mc}"]
 native=[]
 for i in range(cc):
  ci,ac,su,io,sr,an,cd,sv=struct.unpack_from("<IIIIIIII",b,co+32*i);desc=types[ci]
  if not desc.startswith("Lcom/example/hookme/"):continue
  rows.append(f"CLASS {desc} class_data=0x{cd:x}")
  if not cd: continue
  p=cd;sf,p=u(p);inf,p=u(p);direct,p=u(p);virt,p=u(p)
  for n in (sf,inf):
   idx=0
   for _ in range(n):di,p=u(p);fl,p=u(p);idx+=di
  for group,n in (("direct",direct),("virtual",virt)):
   idx=0
   for _ in range(n):
    di,p=u(p);fl,p=u(p);code,p=u(p);idx+=di
    cls,name=methods[idx]
    rows.append(f"  {group} {name} flags=0x{fl:x} code_off=0x{code:x}")
    if fl&0x100:native.append((dex.name,desc,name,fl,code))
 for d,c,n,f,code in native:rows.append(f"NATIVE {d} {c}->{n} flags=0x{f:x} code_off=0x{code:x}")
 path=root/"analysis"/"dex"/(dex.name+".corrected_report.txt")
 path.write_text("\n".join(rows)+"\n",encoding="utf-8")
 print(f"{dex.name}: app methods report={path} native_methods={sum(1 for x in native if x[0]==dex.name)}")
 for d,c,n,f,code in native:
  if d==dex.name:print(f"  NATIVE {c}->{n} flags=0x{f:x} code_off=0x{code:x}")
