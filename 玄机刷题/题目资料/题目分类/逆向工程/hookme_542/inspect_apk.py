import hashlib
import zipfile
from pathlib import Path
p=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\hookme_542\附件解包\hookme\HookMe.apk')
b=p.read_bytes()
print('APK=',p.resolve())
print('APK_SIZE=',len(b))
print('APK_SHA256=',hashlib.sha256(b).hexdigest())
print('APK_MAGIC=',b[:8].hex())
with zipfile.ZipFile(p) as z:
    print('ZIP_TEST=',z.testzip())
    infos=z.infolist()
    print('ENTRY_COUNT=',len(infos))
    for x in infos:
        print(f'{x.filename}\t{ x.file_size }\t{ x.compress_size }\tCRC={x.CRC:08x}')
    for name in [x.filename for x in infos if x.filename.endswith(('.dex','.so')) or x.filename in ('AndroidManifest.xml','resources.arsc')]:
        data=z.read(name)
        print(f'RECORD name={name} size={len(data)} sha256={hashlib.sha256(data).hexdigest()} magic={data[:16].hex()}')
        if name.endswith('.dex'):
            print('DEX_HEADER=')
            print(data[:0x70].hex(' '))
