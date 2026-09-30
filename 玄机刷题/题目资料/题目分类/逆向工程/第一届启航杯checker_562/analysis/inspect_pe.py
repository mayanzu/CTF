from pathlib import Path
import struct,re
p=Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\第一届启航杯checker_562\analysis\extracted\checker.exe")
b=p.read_bytes(); pe=struct.unpack_from('<I',b,0x3c)[0]
machine,nsec,ts,ptrsym,nsyms,optlen,chars=struct.unpack_from('<HHIIIHH',b,pe+4)
opt=pe+24; magic=struct.unpack_from('<H',b,opt)[0]
imagebase=struct.unpack_from('<I',b,opt+28)[0]
ep=struct.unpack_from('<I',b,opt+16)[0]
print(f'PE32 base={imagebase:#x} entry_RVA={ep:#x} entry_VA={imagebase+ep:#x} timestamp={ts:#x} sections={nsec}')
secs=[]
for i in range(nsec):
 o=opt+optlen+i*40; raw=b[o:o+40]; name=raw[:8].split(b'\0')[0].decode('ascii','replace'); vs,va,rs,ro=struct.unpack_from('<IIII',raw,8); secs.append((name,va,vs,ro,rs)); print(f'SECTION {name}: RVA={va:#x} VS={vs:#x} raw={ro:#x}+{rs:#x}')
def off(rva):
 for name,va,vs,ro,rs in secs:
  if va<=rva<va+max(vs,rs):
   x=ro+(rva-va)
   if x<len(b): return x
 raise ValueError(f'RVA unmapped {rva:#x}')
# Imports: IMAGE_DIRECTORY_ENTRY_IMPORT is data directory #1.
imp_rva,imp_size=struct.unpack_from('<II',b,opt+96+8)
print(f'IMPORT directory RVA={imp_rva:#x} size={imp_size:#x}')
if imp_rva:
 d=off(imp_rva)
 for j in range(100):
  oft,stamp,chain,name_rva,ft=struct.unpack_from('<IIIII',b,d+j*20)
  if not any((oft,stamp,chain,name_rva,ft)): break
  name=b[off(name_rva):].split(b'\0')[0].decode('ascii','replace')
  print('DLL',name)
  t=off(oft or ft)
  for k in range(300):
   val=struct.unpack_from('<I',b,t+k*4)[0]
   if not val: break
   if val&0x80000000: fn=f'ordinal_{val&0xffff}'
   else:
    no=off(val); fn=b[no+2:].split(b'\0')[0].decode('ascii','replace')
   print(' ',fn)
print('=== ASCII strings (len >= 4; file offsets) ===')
for m in re.finditer(rb'[\x20-\x7e]{4,}',b):
 s=m.group().decode('ascii','replace')
 print(f'{m.start():#07x}: {s}')
print('=== UTF16LE strings (len >= 4) ===')
# Deliberately only print printable UTF-16 runs; stop at NUL code unit.
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){4,}',b):
 print(f'{m.start():#07x}: {m.group().decode("utf-16le","replace")}')
