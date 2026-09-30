from pathlib import Path
from zipfile import ZipFile
import hashlib

paths = [Path(str(Path(__file__).resolve().parents[1] / '附件' / '像素囚笼附件.zip')),
         Path(str(Path(__file__).resolve().parents[1] / '附件' / '像素囚笼附件 (1).zip'))]
extracted = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png')).read_bytes()
print("extracted challenge.png sha256:", hashlib.sha256(extracted).hexdigest())
for path in paths:
    with ZipFile(path) as archive:
        print("ARCHIVE:", path.name)
        for info in archive.infolist():
            data = archive.read(info.filename)
            print(info.filename, "size", info.file_size, "crc", hex(info.CRC),
                  "sha256", hashlib.sha256(data).hexdigest(),
                  "same as extracted", data == extracted)
