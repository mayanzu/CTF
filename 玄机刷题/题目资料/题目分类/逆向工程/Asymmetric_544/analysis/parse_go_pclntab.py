import pathlib,struct,sys,re
b=pathlib.Path(sys.argv[1]).read_bytes(); u32=lambda o:struct.unpack_from('<I',b,o)[0]; i32=lambda o:struct.unpack_from('<i',b,o)[0]; u64=lambda o:struct.unpack_from('<Q',b,o)[0]
magic=b'\xf1\xff\xff\xff\x00\x00\x01\x08'; hs=[]; pos=0
while True:
 p=b.find(magic,pos)
 if p<0:break
 hs.append(p);pos=p+1
print('pclntab candidates:',[hex(x) for x in hs])
for h in hs:
 nfunc=u64(h+8); nfiles=u64(h+16); text=u64(h+24); fn=u64(h+32); cu=u64(h+40); filetab=u64(h+48); pctab=u64(h+56); pcln=u64(h+64)
 print(f'header=0x{h:x} nfunc={nfunc} nfiles={nfiles} text=0x{text:x} funcname=0x{fn:x} cu=0x{cu:x} filetab=0x{filetab:x} pctab=0x{pctab:x} pcln=0x{pcln:x}')
 base=h+pcln; names=h+fn
 for idx in range(min(nfunc,3)):
  ent=u32(base+8*idx); fo=u32(base+8*idx+4); no=i32(base+fo+4); nm=b[names+no:names+no+160].split(b'\0')[0]
  print(' sample',idx,'entryoff',hex(ent),'funcoff',hex(fo),'nameoff',no,'name',nm.decode('utf8','replace'))
 found=[]; app=[]
 for idx in range(nfunc):
  ent=u32(base+8*idx); fo=u32(base+8*idx+4)
  if fo>=len(b)-base:continue
  no=i32(base+fo+4); q=names+no
  if q<0 or q>=len(b):continue
  nm=b[q:q+256].split(b'\0')[0].decode('utf8','replace')
  if any(x in nm.lower() for x in ['main.', 'asymmetric', 'rsa', 'encrypt', 'decrypt', 'flag']): found.append((ent,fo,nm))
  if nm.startswith('main.') or nm.startswith('crypto/rsa') or nm.startswith('math/big') and len(app)<50: app.append((ent,fo,nm))
 print('matching funcs:')
 for ent,fo,nm in found:print(f'  VA=0x{text+ent:x} rva=0x{text+ent-0x400000:x} funcoff=0x{fo:x} {nm}')
 print('main/rsa funcs:')
 for ent,fo,nm in app:print(f'  VA=0x{text+ent:x} rva=0x{text+ent-0x400000:x} {nm}')
