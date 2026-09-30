import hashlib
import re
import zipfile
from pathlib import Path

apk=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\hookme_542\附件解包\hookme\HookMe.apk')
out=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\hookme_542\代码附件')
out.mkdir(parents=True,exist_ok=True)
keep=[]
with zipfile.ZipFile(apk) as z:
    for info in z.infolist():
        name=info.filename
        if re.fullmatch(r'classes(?:\d+)?\.dex',name) or name=='AndroidManifest.xml' or re.fullmatch(r'lib/[^/]+/libhookme\.so',name):
            keep.append(info)
    print('APK=',apk)
    print('APK_SHA256=',hashlib.sha256(apk.read_bytes()).hexdigest())
    print('RELEVANT_ENTRY_COUNT=',len(keep))
    for info in keep:
        name=info.filename
        data=z.read(name)
        target=out.joinpath(*Path(name).parts)
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(data)
        print(f'ENTRY={name}\tsize={len(data)}\tsha256={hashlib.sha256(data).hexdigest()}\tmagic={data[:12].hex()}')
        if name.endswith('.dex') or name.endswith('.so') or name=='AndroidManifest.xml':
            text_runs=[m.group().decode('ascii','replace') for m in re.finditer(rb'[\x20-\x7e]{4,}',data)]
            pat=re.compile(r'flag|hook|frida|xposed|jni|native|root|ptrace|check|secret|key|MainActivity|Main|tamper|debug|magisk|zygisk|com\.',re.I)
            relevant=[]
            seen=set()
            for s in text_runs:
                if pat.search(s) and s not in seen:
                    relevant.append(s);seen.add(s)
            print(f'FILTERED_ASCII_COUNT={len(relevant)}')
            for s in relevant[:300]:
                print('STR=',repr(s))
print('EXTRACTED_TO=',out)
