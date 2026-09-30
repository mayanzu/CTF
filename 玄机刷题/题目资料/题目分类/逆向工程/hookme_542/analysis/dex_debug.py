from pathlib import Path
import struct
b=(Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\hookme_542\analysis\components\classes4.dex")).read_bytes()
def u(p):
 v=s=0
 while 1:
  x=b[p];p+=1;v|=(x&127)<<s
  if x<128:return v,p
  s+=7
sc,so=struct.unpack_from("<II",b,0x38); strings=[]
for i in range(sc):
 p=struct.unpack_from("<I",b,so+4*i)[0];_,p=u(p);e=b.index(b"\0",p);strings.append(b[p:e].decode("utf8","replace"))
tc,to=struct.unpack_from("<II",b,0x40); tid=[struct.unpack_from("<I",b,to+4*i)[0] for i in range(tc)]; types=[strings[x] for x in tid]
mc,mo=struct.unpack_from("<II",b,0x58); methods=[]
for i in range(mc): c,pr,n=struct.unpack_from("<HHI",b,mo+8*i);methods.append((types[c],strings[n]))
cc,co=struct.unpack_from("<II",b,0x60);print("cc",cc,"mc",mc)
for i in range(cc):
 ci,ac,su,io,sr,an,cd,sv=struct.unpack_from("<IIIIIIII",b,co+32*i); d=types[ci]
 if not d.startswith("Lcom/example/hookme/"):continue
 p=cd;sf,p=u(p);inf,p=u(p);dc,p=u(p);vc,p=u(p);print("CLASS",d,"cd",hex(cd),"sf/inf/direct/virt",sf,inf,dc,vc)
 for n in (sf,inf):
  idx=0
  for _ in range(n):di,p=u(p);fl,p=u(p);idx+=di
 for group,n in (("direct",dc),("virtual",vc)):
  idx=0
  for _ in range(n):
   di,p=u(p);fl,p=u(p);code,p=u(p);idx+=di
   print(group,idx,methods[idx],hex(fl),hex(code),"native?",bool(fl&0x100))
