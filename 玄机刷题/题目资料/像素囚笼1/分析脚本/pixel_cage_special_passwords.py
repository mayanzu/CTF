from pathlib import Path
from zipfile import ZipFile

image = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
raw = [b"", b"\x00", b"\x00" * 4, b"\xef\xbb\xbf", b"\r\n", b" ", b"  ", b"\t"]
phrases = [b"Abstract Art Gallery", b" abstractartgallery", b"abstractartgallery ",
           b"\tabstractartgallery", b"abstractartgallery\n", b"abstractartgallery\r\n"]
with ZipFile(image) as archive:
    for password in raw + phrases:
        try:
            data = archive.read("secret.txt", pwd=password)
        except Exception as exc:
            print("rejected", repr(password), type(exc).__name__)
            continue
        print("PASSWORD FOUND:", repr(password))
        print("SECRET.TXT:", data.decode(errors="replace"))
        break
    else:
        print("No empty/control/whitespace password matched.")
