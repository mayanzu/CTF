from pathlib import Path
from zipfile import ZipFile
import colorsys, hashlib
image=Path(__file__).resolve().parents[1]/'附件'/'challenge.png'
seq=['blue','red','yellow','green','purple','cyan','blue','red']
colors={'blue':(66,133,244),'red':(219,68,55),'yellow':(244,180,0),'green':(15,157,88),'purple':(171,71,188),'cyan':(0,172,193)}
features={}
for name,(r,g,b) in colors.items():
    h,s,v=colorsys.rgb_to_hsv(r/255,g/255,b/255)
    features[name]={
      'r':r,'g':g,'b':b,'sum':r+g+b,'xor':r^g^b,'min':min(r,g,b),'max':max(r,g,b),
      'hue_deg':round(h*360),'hue_sector':round(h*6),'sat_pct':round(s*100),'val_pct':round(v*100),
      'name_len':len(name),'first':ord(name[0])-96,'last':ord(name[-1])-96,
      'lettersum':sum(ord(c)-96 for c in name),'asciisum':sum(map(ord,name)),
    }
candidates=set()
for feature in next(iter(features.values())):
    vals=[features[c][feature] for c in seq]
    forms=set()
    for values in (vals,vals[::-1]):
      for sep in ('','-', '_', ':', ',', '.', ' '):
        forms.add(sep.join(map(str,values)))
        forms.add(sep.join(f'{x:02d}' for x in values))
        forms.add(sep.join(f'{x:03d}' for x in values))
        forms.add(sep.join(f'{x:X}' for x in values))
        forms.add(sep.join(f'{x:02X}' for x in values))
    for modulus in (10,26,36,95,256):
      for offset in range(modulus):
        mapped=[(v+offset)%modulus for v in vals]
        forms.add(''.join(map(str,mapped)))
        if modulus==26:
          forms.add(''.join(chr(65+x) for x in mapped)); forms.add(''.join(chr(97+x) for x in mapped))
        if modulus==95:
          forms.add(''.join(chr(32+x) for x in mapped))
        if modulus==256:
          forms.add(bytes(mapped).hex()); forms.add(bytes(mapped).hex().upper())
    for base in list(forms):
      raw=base.encode('latin1',errors='ignore')
      for fn in (hashlib.md5,hashlib.sha1,hashlib.sha256,hashlib.sha512):
        d=fn(raw).digest(); forms.add(d.hex()); forms.add(d.hex().upper())
    candidates.update(forms)
print('features:',len(features[next(iter(features))]))
print('exact-palette feature candidates:',len(candidates))
hits=[]
with ZipFile(image) as z:
    for pwd in candidates:
      try: hits.append((pwd,z.read('secret.txt',pwd=pwd.encode('latin1')))); break
      except Exception: pass
print('full ZIP decrypt + CRC hits:',len(hits))
for pwd,out in hits: print('PASSWORD:',repr(pwd),'SECRET:',repr(out))

