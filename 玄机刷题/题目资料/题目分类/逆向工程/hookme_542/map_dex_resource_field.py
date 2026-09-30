import pathlib,struct,hashlib
root=pathlib.Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\hookme_542\代码附件')
def uleb(b,o):
 v=s=0
 while True:
  x=b[o];o+=1;v|=(x&127)<<s
  if x<128:return v,o
  s+=7
def parse(p):
 b=p.read_bytes();u16=lambda o:struct.unpack_from('<H',b,o)[0];u32=lambda o:struct.unpack_from('<I',b,o)[0]
 strings=[]
 for i in range(u32(0x38)):
  q=u32(u32(0x3c)+4*i);n=0;shift=0
  while True:
   x=b[q];q+=1;n|=(x&127)<<shift
   if x<128:break
   shift+=7
  end=b.index(0,q);strings.append(b[q:end].replace(b'\xc0\x80',b'\0').decode('utf8','replace'))
 types=[strings[u32(u32(0x44)+4*i)] for i in range(u32(0x40))]
 fields=[];nf=u32(0x50);fo=u32(0x54)
 for i in range(nf):
  c,t,n=struct.unpack_from('<HHI',b,fo+8*i);fields.append((types[c],types[t],strings[n]))
 print('\nDEX',p.name,'sha256',hashlib.sha256(b).hexdigest(),'field_count',nf)
 for i,f in enumerate(fields):
  if 'com/example/hookme' in f[0] and (i<24 or '$string' in f[0]):print('FIELD_ID',i,f)
 csz=u32(0x60);co=u32(0x64)
 for ci in range(csz):
  class_idx,acc,sup,inter,src,ann,cd,sv=struct.unpack_from('<8I',b,co+32*ci)
  desc=types[class_idx]
  if desc!='Lcom/example/hookme/R$string;':continue
  print('TARGET_CLASS',desc,'class_data',hex(cd),'static_values',hex(sv))
  sf,off=uleb(b,cd);inf,off=uleb(b,off);dm,off=uleb(b,off);vm,off=uleb(b,off)
  idx=0
  for _ in range(sf):
   d,off=uleb(b,off);idx+=d;flags,off=uleb(b,off)
   print('STATIC_FIELD',idx,fields[idx],'access',hex(flags))
parse(root/'classes4.dex')
parse(root/'classes2.dex')
