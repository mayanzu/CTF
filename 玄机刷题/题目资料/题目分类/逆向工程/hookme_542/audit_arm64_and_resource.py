import pathlib,struct,hashlib,subprocess,sys
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
root=pathlib.Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\hookme_542')
# Parse R$string class field constants and identify correct_ciphertext resource ID.
p=root/'代码附件'/'classes2.dex';b=p.read_bytes();u32=lambda o:struct.unpack_from('<I',b,o)[0];u16=lambda o:struct.unpack_from('<H',b,o)[0]
def uleb(o):
 v=s=0
 while True:
  x=b[o];o+=1;v|=(x&127)<<s
  if x<128:return v,o
  s+=7
def sval(o):
 n,o=uleb(o);end=b.index(0,o);return b[o:end].decode('utf8','replace'),end+1
strings=[sval(u32(u32(0x3c)+4*i))[0] for i in range(u32(0x38))]
types=[strings[u32(u32(0x44)+4*i)] for i in range(u32(0x40))]
flds=[];fo=u32(0x54)
for i in range(u32(0x50)):
 c,t,n=struct.unpack_from('<HHI',b,fo+8*i);flds.append((types[c],types[t],strings[n]))
found=[];co=u32(0x64)
for ci in range(u32(0x60)):
 cidx,acc,sup,inter,src,ann,cd,sv=struct.unpack_from('<8I',b,co+32*ci)
 if types[cidx]!='Lcom/example/hookme/R$string;':continue
 sf,off=uleb(cd);inf,off=uleb(off);dm,off=uleb(off);vm,off=uleb(off);idx=0
 for _ in range(sf):
  d,off=uleb(off);idx+=d;af,off=uleb(off);found.append(idx)
 arr,off=uleb(sv);vals=[]
 for _ in range(arr):
  h=b[off];off+=1;typ=h&31;argc=(h>>5)+1;raw=int.from_bytes(b[off:off+argc],'little');off+=argc
  if typ==4 and raw&(1<<(8*argc-1)):raw-=1<<(8*argc)
  vals.append((typ,raw))
 print('R_STRING_STATIC_FIELD_COUNT',len(found),'ENCODED_VALUES',vals)
 for fid,val in zip(found,vals):print('R_STRING_FIELD',flds[fid],'VALUE_TYPE',val[0],'RESOURCE_ID',f'0x{val[1]&0xffffffff:08x}')
print('DEX2_SHA256',hashlib.sha256(b).hexdigest())
# ELF64 ARM64 section/symbol parsing for native cross-ABI verification.
e=root/'代码附件'/'lib'/'arm64-v8a'/'libhookme.so';d=e.read_bytes();assert d[:4]==b'\x7fELF' and d[4]==2 and d[5]==1
shoff=struct.unpack_from('<Q',d,0x28)[0];shentsize=struct.unpack_from('<H',d,0x3a)[0];shnum=struct.unpack_from('<H',d,0x3c)[0];shstrndx=struct.unpack_from('<H',d,0x3e)[0]
sh=[]
for i in range(shnum):sh.append(struct.unpack_from('<IIQQQQIIQQ',d,shoff+i*shentsize))
shstrsec=sh[shstrndx];shstrtab=d[shstrsec[4]:shstrsec[4]+shstrsec[5]]
def cstr(blob,o):return blob[o:blob.find(b'\0',o)].decode('utf8','replace')
named={cstr(shstrtab,s[0]):s for s in sh}
textsec=named['.text'];textaddr,textoff,textsize=textsec[3],textsec[4],textsec[5]
print('\nARM64_FILE',e,'SIZE',len(d),'SHA256',hashlib.sha256(d).hexdigest(),'TEXT_VADDR',hex(textaddr),'TEXT_FILEOFF',hex(textoff),'TEXT_SIZE',hex(textsize))
func_names={'Java_com_example_hookme_MainActivity_setPackageNameToNative','Java_com_example_hookme_MainActivity_rc4Encrypt'}
syms=[]
for secname,sec in named.items():
 if sec[1] not in (2,11) or sec[9]==0:continue
 strsec=sh[sec[6]];strtab=d[strsec[4]:strsec[4]+strsec[5]]
 for off in range(sec[4],sec[4]+sec[5],sec[9]):
  no,info,other,ndx,val,size=struct.unpack_from('<IBBHQQ',d,off);name=cstr(strtab,no)
  if name in func_names or 'rc4Encrypt' in name or 'initializeSBox' in name or '_Z3ksa' in name or '_Z4prga' in name or name=='globalKey':
   syms.append((name,val,size,ndx))
for x in syms:print('ARM64_SYMBOL',x)
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
for name,val,size,ndx in syms:
 if name not in func_names and 'rc4Encrypt' not in name and 'initializeSBox' not in name and '_Z3ksa' not in name and '_Z4prga' not in name:continue
 if size==0 or val<textaddr or val+size>textaddr+textsize:continue
 code=d[textoff+(val-textaddr):textoff+(val-textaddr)+size]
 print('\nARM64_DISASSEMBLY',name,'size',size)
 for ins in md.disasm(code,val):print(f'  {ins.address:08x}: {ins.mnemonic:8s} {ins.op_str}')



