import pathlib,zipfile,hashlib,struct,sys
root=pathlib.Path(sys.argv[1]); zpath=root/'originals'/'Asymmetric_flag.zip'; exe=root/'extracted'/'Asymmetric_flag.exe'; archive=zipfile.ZipFile(zpath)
print('archive members:')
for i in archive.infolist():
 print(f'  {i.filename} uncompressed={i.file_size} compressed={i.compress_size} crc32={i.CRC:08x}')
 data=archive.read(i.filename)
 if i.filename.lower().endswith('.exe'):
  print('  archive_member_sha256=',hashlib.sha256(data).hexdigest().upper())
  print('  extracted_sha256    =',hashlib.sha256(exe.read_bytes()).hexdigest().upper())
  print('  byte_identical       =',data==exe.read_bytes())
# Decode Go string header passed for the initial prompt; VA header 0x4eb610 stores pointer, length.
b=exe.read_bytes(); pe=struct.unpack_from('<I',b,0x3c)[0]; sh=pe+24+struct.unpack_from('<H',b,pe+20)[0]; sections=[]
for j in range(struct.unpack_from('<H',b,pe+6)[0]):
 s=sh+40*j; nm=b[s:s+8].split(b'\0')[0].decode(); vs,va,rs,rp=struct.unpack_from('<IIII',b,s+8); sections.append((nm,va,max(vs,rs),rp))
def vaoff(va):
 rva=va-0x400000
 for nm,va0,size,rp in sections:
  if va0<=rva<va0+size:return rp+rva-va0
 raise ValueError(hex(va))
head=vaoff(0x4eb610); ptr,n=struct.unpack_from('<QQ',b,head); msg=b[vaoff(ptr):vaoff(ptr)+n]
print(f'prompt_string_header=VA 0x4eb610 -> data VA 0x{ptr:x}, length={n}, bytes={msg!r}')
