from pathlib import Path
import base64, hashlib, re, subprocess
root=Path(__file__).resolve().parents[1]
analysis=root/'analysis'
index=(root/'附件'/'hap_contents'/'resources.index').read_bytes()
hits=[]
for m in re.finditer(rb'[A-Za-z0-9+/]{24,}={0,2}',index):
    try: raw=base64.b64decode(m.group(),validate=True)
    except Exception: continue
    if raw.startswith(b'Salted__'): hits.append((m,raw))
if len(hits)!=1: raise SystemExit(f'expected one OpenSSL Salted__ blob; found {len(hits)}')
m,raw=hits[0]
encoded=m.group()
offset=m.start()
(analysis/'resource_index_salted_ciphertext.b64').write_bytes(encoded)
print(f'INDEX_SIZE={len(index)}')
print(f'SALTED_B64_OFFSET={offset} BASE64_LENGTH={len(encoded)}')
print(f'SALTED_B64={encoded.decode("ascii")}')
print(f'DECODED_LENGTH={len(raw)} HEADER={raw[:16].hex()} SALT={raw[8:16].hex()} CIPHERTEXT_BYTES={len(raw)-16}')
assert raw[:8]==b'Salted__' and (len(raw)-16)%16==0
img=(analysis/'enc.recovered.jpg').read_bytes()
img64=base64.b64encode(img)
password=hashlib.md5(img64).hexdigest()
print(f'JPEG_SIZE={len(img)} JPEG_SHA256={hashlib.sha256(img).hexdigest()} JPEG_BASE64_SIZE={len(img64)}')
print(f'MD5_OF_JPEG_BASE64={password}')
exe=Path(r'C:\msys64\mingw64\bin\openssl.exe')
if not exe.exists(): raise SystemExit(f'OpenSSL executable missing: {exe}')
cmd=[str(exe),'enc','-d','-aes-256-cbc','-md','md5','-a','-A','-pass','pass:'+password]
print('OPENSSL_COMMAND='+' '.join(cmd))
proc=subprocess.run(cmd,input=encoded,capture_output=True)
print(f'OPENSSL_EXIT={proc.returncode} PLAINTEXT_LENGTH={len(proc.stdout)} STDERR={proc.stderr.decode("utf-8","replace")!r}')
print(f'PLAINTEXT_HEX={proc.stdout.hex()}')
text=proc.stdout.decode('utf-8')
print(f'PLAINTEXT_REPR={text!r}')
if proc.returncode: raise SystemExit(proc.returncode)
(analysis/'hint_plaintext.txt').write_text(text,encoding='utf-8')
example='012345678Harmony5337'
print(f'EXAMPLE_INPUT={example!r} EXAMPLE_MD5={hashlib.md5(example.encode()).hexdigest()}')
pattern='137524860'
candidate=hashlib.md5((pattern+'Harmony5337').encode()).hexdigest()
print(f'PATTERN={pattern} HINT_RULE_INPUT={(pattern+"Harmony5337")!r} CANDIDATE=flag{{{candidate}}}')
print('PLATFORM_ACCEPTANCE=NOT_TESTED_BY_THIS_SUBTASK')
