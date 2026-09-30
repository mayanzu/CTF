#!/usr/bin/env python3
"""Offline metadata inspection for ParlooChecker APK; never executes the APK."""
from pathlib import PurePosixPath
from zipfile import ZipFile
import hashlib
import sys

apk = sys.argv[1]
data_hash = hashlib.sha256(open(apk, "rb").read()).hexdigest().upper()
print(f"APK={apk}")
print(f"SHA256={data_hash}")
unsafe = []
with ZipFile(apk) as zf:
    infos = zf.infolist()
    print(f"ENTRY_COUNT={len(infos)}")
    total = 0
    for info in infos:
        name = info.filename.replace("\\", "/")
        parts = PurePosixPath(name).parts
        bad = name.startswith("/") or (len(name) >= 2 and name[1] == ":") or ".." in parts
        if bad:
            unsafe.append(info.filename)
        total += info.file_size
        print(
            f"ENTRY name={info.filename!r} size={info.file_size} "
            f"compressed={info.compress_size} crc32={info.CRC:08x} "
            f"directory={info.is_dir()} unsafe={bad}"
        )
    print(f"TOTAL_UNCOMPRESSED={total}")
    print(f"UNSAFE_ENTRY_COUNT={len(unsafe)}")
    for item in unsafe:
        print(f"UNSAFE_ENTRY={item!r}")
