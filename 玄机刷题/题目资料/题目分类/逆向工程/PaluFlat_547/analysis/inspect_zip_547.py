from zipfile import ZipFile
from pathlib import Path
import hashlib
p = Path(__file__).parents[1] / "originals" / "PaluFlat_flag.zip"
print("ZIP_PATH=", p)
print("ZIP_SHA256=", hashlib.sha256(p.read_bytes()).hexdigest().upper())
with ZipFile(p) as z:
    print("ZIP_TEST=", z.testzip())
    for info in z.infolist():
        print(f"ENTRY={info.filename!r} SIZE={info.file_size} COMPRESSED={info.compress_size}")
        print("ENTRY_SHA256=" + hashlib.sha256(z.read(info)).hexdigest().upper())
