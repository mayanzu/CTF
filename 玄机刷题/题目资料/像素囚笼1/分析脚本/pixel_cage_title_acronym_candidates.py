from pathlib import Path
from zipfile import ZipFile
p=Path(r'D:\Downloads\像素囚笼附件 (1)\challenge.png')
words=['Abstract','Art','Gallery']
forms=set()
for sep in ('',' ','-','_','.'): forms.add(sep.join(words))
for sep in ('',' ','-','_','.'): forms.add(sep.join(w.lower() for w in words)); forms.add(sep.join(w.upper() for w in words))
for order in (words,words[::-1]):
  for sep in ('',' ','-','_','.'): forms.add(sep.join(w[0] for w in order)); forms.add(sep.join(w[0].lower() for w in order))
  for sep in ('',' ','-','_','.'): forms.add(sep.join(w[-1] for w in order)); forms.add(sep.join(w[-1].lower() for w in order))
forms.update(['AAGallery','aagallery','AAG583','AAG2026','AAG1','AAG123','aag583','aag2026','aa_g','a-a-g','a.a.g','a_a_g','abstract_art_gallery','abstract-art-gallery','abstract.art.gallery','Abstract_Art_Gallery','Abstract-Art-Gallery','Abstract.Art.Gallery'])
candidates=set(forms)
for word in list(forms):
  for suffix in ('1','01','123','2026','583','!','@'):
    candidates.add(word+suffix)
    for sep in ('_','-','.'): candidates.add(word+sep+suffix)
with ZipFile(p) as z:
  for password in sorted(candidates):
    try:
      data=z.read('secret.txt',pwd=password.encode('utf-8'))
      print('PASSWORD FOUND:',repr(password)); print('SECRET.TXT:',data.decode(errors='replace')); break
    except Exception: pass
  else: print('No match across',len(candidates),'title phrase/acronym and suffix candidates.')
