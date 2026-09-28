from pathlib import Path
from zipfile import ZipFile
p=Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
roots='pixel pixelcage pixel-cage pixelprison xiangsulong xiangsuqiulong xuanji edisec anwangbei anwangbei2026 Abstract abstract art gallery abstractartgallery color colors colour colorful circle circles square squares BRYGPCBR BRYGPC 13524613 12345612 02413502 4285F4 RGB MISC secret challenge'.split()
suffixes=['','1','01','2026','583','1!','!']
prefixes=['','1','2026','583']
seps=['','_','-','.', ' ']
candidates=set()
for word in roots:
    variants={word,word.lower(),word.upper(),word.title()}
    for w in variants:
        candidates.add(w)
        for sep in seps:
            for s in suffixes:
                candidates.add(w+sep+s)
            for pre in prefixes:
                candidates.add(pre+sep+w)
with ZipFile(p) as z:
    print('candidate count:',len(candidates))
    for password in sorted(candidates):
        try:
            data=z.read('secret.txt',pwd=password.encode())
            print('PASSWORD FOUND:',repr(password)); print('SECRET.TXT:',data.decode(errors='replace')); break
        except Exception: pass
    else: print('No challenge keyword + common year/number pattern matched.')
