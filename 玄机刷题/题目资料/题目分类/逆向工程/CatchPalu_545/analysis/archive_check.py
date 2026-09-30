import hashlib, pathlib, zipfile
root=pathlib.Path(__file__).resolve().parents[1]
zp=root/'originals'/'CatchPalu_flag.zip'; ep=root/'extracted'/'CatchPalu_flag.exe'
exe=ep.read_bytes(); print('ZIP_SHA256='+hashlib.sha256(zp.read_bytes()).hexdigest())
with zipfile.ZipFile(zp) as z:
 for i in z.infolist():
  print(f'ZIP_MEMBER={i.filename} size={i.file_size} compressed={i.compress_size} crc32={i.CRC:08x}')
  data=z.read(i); print('MEMBER_SHA256='+hashlib.sha256(data).hexdigest())
  if i.filename.lower().endswith('.exe'):
   print('MATCHES_EXTRACTED_EXE='+str(data==exe))
   assert data==exe
print('ARCHIVE_CHECK=PASS')
