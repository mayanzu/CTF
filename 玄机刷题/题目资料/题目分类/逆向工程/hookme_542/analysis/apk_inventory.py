from pathlib import Path
from zipfile import ZipFile
import hashlib
apk = Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\hookme_542\附件解包\hookme\HookMe.apk")
print(f"APK={apk}")
print(f"APK_SIZE={apk.stat().st_size}")
print(f"APK_SHA256={hashlib.sha256(apk.read_bytes()).hexdigest().upper()}")
with ZipFile(apk) as zf:
    print(f"ZIP_ENTRIES={len(zf.infolist())}")
    print("NAME\tSIZE\tCOMPRESSED\tCRC32\tSHA256")
    for zi in sorted(zf.infolist(), key=lambda x: x.filename):
        if zi.is_dir():
            print(f"{zi.filename}/\t0\t0\t{zi.CRC:08X}\t-")
            continue
        data = zf.read(zi)
        print(f"{zi.filename}\t{zi.file_size}\t{zi.compress_size}\t{zi.CRC:08X}\t{hashlib.sha256(data).hexdigest().upper()}")
