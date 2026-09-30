from pathlib import Path
from zipfile import ZipFile
p=Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
candidates='pixel pixelcage pixel-cage pixel_cage pixelcage1 pixelprison xiangsulong xiangsuaqiu long xiansuqiulong xiangs囚笼 xuanji edisec anwangbei anwang2026 2026anwangbei MISC misc flag secret password gallery art abstract abstractart abstract-art RGB rgb BGR bgr'.split()
with ZipFile(p) as z:
    for password in candidates:
        try:
            data=z.read('secret.txt',pwd=password.encode())
            print('PASSWORD FOUND:',repr(password)); print(data.decode(errors='replace')); break
        except Exception as exc: print('rejected:',repr(password),type(exc).__name__)
    else: print('No short topic keyword matched.')
