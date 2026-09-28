import zipfile,re,pathlib,hashlib,struct
apk=pathlib.Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\hookme_542\附件解包\hookme\HookMe.apk')
with zipfile.ZipFile(apk) as z:
 man=z.read('AndroidManifest.xml'); arsc=z.read('resources.arsc')
print('APK',apk,'SHA256',hashlib.sha256(apk.read_bytes()).hexdigest())
print('MANIFEST_BYTES',len(man),'SHA256',hashlib.sha256(man).hexdigest())
# Parse Android binary XML string pool.
def u16(b,o):return struct.unpack_from('<H',b,o)[0]
def u32(b,o):return struct.unpack_from('<I',b,o)[0]
def len8(b,o):
 a=b[o];o+=1
 if a&0x80:a=((a&0x7f)<<8)|b[o];o+=1
 return a,o
def len16(b,o):
 a=u16(b,o);o+=2
 if a&0x8000:a=((a&0x7fff)<<16)|u16(b,o);o+=2
 return a,o
# first chunk is XML; locate string pool chunk
pos=8; pool=None
while pos+8<=len(man):
 typ=u16(man,pos); hs=u16(man,pos+2); sz=u32(man,pos+4)
 if sz<8 or pos+sz>len(man):raise ValueError(('bad AXML chunk',pos,typ,sz))
 if typ==1:
  cnt=u32(man,pos+8);flags=u32(man,pos+16);start=u32(man,pos+20);utf8=bool(flags&0x100); entries=[]
  for i in range(cnt):
   off=u32(man,pos+hs+4*i);q=pos+start+off
   if utf8:
    _,q=len8(man,q);n,q=len8(man,q);end=man.index(0,q);s=man[q:end].decode('utf-8','replace')
   else:
    n,q=len16(man,q);s=man[q:q+2*n].decode('utf-16le','replace')
   entries.append(s)
  pool=entries;poolpos=pos;break
 pos+=sz
if pool is None:raise ValueError('AXML string pool missing')
print('AXML_STRING_COUNT',len(pool),'UTF8',utf8)
print('AXML_PACKAGE_LIKE',[s for s in pool if 'com.' in s or 'hookme' in s.lower()])
# Find manifest start element and its package attribute.
pos=poolpos
package=None
while pos+8<=len(man):
 typ=u16(man,pos);hs=u16(man,pos+2);sz=u32(man,pos+4)
 if typ==0x0102:
  ext=pos+16; ns=u32(man,ext); name=u32(man,ext+4)
  attr_start=u16(man,ext+8); attr_size=u16(man,ext+10); count=u16(man,ext+12)
  tag=pool[name] if name!=0xffffffff else ''
  if tag=='manifest':
   base=ext+attr_start
   for i in range(count):
    a=base+i*attr_size; an=u32(man,a+4); raw=u32(man,a+8); vt=man[a+15]; val=u32(man,a+16)
    attr=pool[an] if an!=0xffffffff else ''
    if attr=='package':package=pool[raw] if raw!=0xffffffff else (pool[val] if vt==3 else str(val))
    print('MANIFEST_ATTR',attr,'raw',pool[raw] if raw!=0xffffffff else None,'typed',vt,val)
 if sz<8 or pos+sz>len(man):break
 pos+=sz
print('PACKAGE_NAME',repr(package))
# Recover actual ASCII hex resource string. Prior printable run included the two one-byte UTF8 lengths 0x4c,0x4c.
hexes=re.findall(rb'(?<![0-9A-Fa-f])([0-9A-Fa-f]{64,})(?![0-9A-Fa-f])',arsc)
print('LONG_HEX_STRINGS',len(hexes))
for h in hexes:
 text=h.decode(); print('CIPHER_HEX_LEN',len(text),'CIPHER_HEX',text)
 if package:
  key=package.encode()
  S=list(range(256));j=0
  for i in range(256):j=(j+S[i]+key[i%len(key)])&255;S[i],S[j]=S[j],S[i]
  i=j=0;plain=bytearray()
  for c in bytes.fromhex(text):
   i=(i+1)&255;j=(j+S[i])&255;S[i],S[j]=S[j],S[i];plain.append(c^S[(S[i]+S[j])&255])
  print('DECRYPTED_HEX',plain.hex())
  print('DECRYPTED_BYTES',repr(bytes(plain)))
  try: print('DECRYPTED_UTF8',bytes(plain).decode('utf-8'))
  except UnicodeDecodeError as e: print('UTF8_ERROR',e)
  print('FLAG_FORMAT',bool(re.fullmatch(rb'flag\{[^\r\n{}]+\}',plain,re.I)))
