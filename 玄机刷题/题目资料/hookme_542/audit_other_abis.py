import pathlib,struct,hashlib
from capstone import Cs,CS_ARCH_ARM,CS_ARCH_X86,CS_MODE_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN,CS_MODE_32
root=pathlib.Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\hookme_542\代码附件\lib')
for rel in ['armeabi-v7a/libhookme.so','x86/libhookme.so']:
 p=root/rel;b=p.read_bytes();is64=b[4]==2;assert b[5]==1
 mach=struct.unpack_from('<H',b,18)[0]
 if is64:
  shoff=struct.unpack_from('<Q',b,0x28)[0];ents=struct.unpack_from('<H',b,0x3a)[0];n=struct.unpack_from('<H',b,0x3c)[0];si=struct.unpack_from('<H',b,0x3e)[0]
  sh=[struct.unpack_from('<IIQQQQIIQQ',b,shoff+i*ents) for i in range(n)]
 else:
  shoff=struct.unpack_from('<I',b,0x20)[0];ents=struct.unpack_from('<H',b,0x2e)[0];n=struct.unpack_from('<H',b,0x30)[0];si=struct.unpack_from('<H',b,0x32)[0]
  sh=[struct.unpack_from('<IIIIIIIIII',b,shoff+i*ents) for i in range(n)]
 namesec=sh[si];names=b[namesec[4]:namesec[4]+namesec[5]]
 def cstr(x,o):return x[o:x.find(b'\0',o)].decode('utf8','replace')
 named={cstr(names,s[0]):s for s in sh};tx=named['.text'];tva,toff,tsize=tx[3],tx[4],tx[5]
 print('\nABI',rel,'machine',mach,'size',len(b),'SHA256',hashlib.sha256(b).hexdigest(),'TEXT',hex(tva),hex(toff),hex(tsize))
 funcs=[]
 for sn,sec in named.items():
  if sec[1] not in (2,11) or sec[9]==0:continue
  st=sh[sec[6]];strtab=b[st[4]:st[4]+st[5]]
  step=sec[9]
  for o in range(sec[4],sec[4]+sec[5],step):
   if is64:no,info,other,ndx,val,size=struct.unpack_from('<IBBHQQ',b,o)
   else:no,val,size,info,other,ndx=struct.unpack_from('<IIIBBH',b,o)
   name=cstr(strtab,no)
   if name in ('Java_com_example_hookme_MainActivity_setPackageNameToNative','Java_com_example_hookme_MainActivity_rc4Encrypt') or any(x in name for x in ['initializeSBox','rc4Encrypt','_Z3ksa','_Z4prga']):
    row=(name,val,size,ndx)
    if row not in funcs:funcs.append(row)
 for x in funcs:print('SYMBOL',x)
 if mach==40:arch=CS_ARCH_ARM;mode=CS_MODE_LITTLE_ENDIAN
 elif mach==3:arch=CS_ARCH_X86;mode=CS_MODE_32
 else:continue
 md=Cs(arch,mode)
 for name,val,size,ndx in funcs:
  if size==0 or val<tva or val>=tva+tsize:continue
  thumb=mach==40 and bool(val&1);start=val&~1 if thumb else val
  mode=CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN if thumb else (CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN if mach==40 else CS_MODE_32)
  md=Cs(arch,mode)
  off=toff+(start-tva);code=b[off:off+size]
  print('DISASM',name,'thumb',thumb,'size',size)
  for i in md.disasm(code,start): print(f' {i.address:08x}: {i.mnemonic:8s} {i.op_str}')
