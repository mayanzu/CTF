from pathlib import Path
import base64, hashlib, subprocess, sys
sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
root=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\OpenHarmony_secret_561')
analysis=root/'analysis'
cipher_b64=(analysis/'resource_index_salted_ciphertext.b64').read_bytes()
img=(analysis/'enc.recovered.jpg').read_bytes()
full=(analysis/'enc.custom-sm4-decrypted.bin').read_bytes()
img_b64=base64.b64encode(img)
full_b64=base64.b64encode(full)
candidates=[
 ('md5.jpg.b64.lower',hashlib.md5(img_b64).hexdigest()),
 ('md5.jpg.b64.upper',hashlib.md5(img_b64).hexdigest().upper()),
 ('md5.jpg.bytes.lower',hashlib.md5(img).hexdigest()),
 ('md5.jpg.bytes.upper',hashlib.md5(img).hexdigest().upper()),
 ('md5.full.b64.lower',hashlib.md5(full_b64).hexdigest()),
 ('md5.full.bytes.lower',hashlib.md5(full).hexdigest()),
 ('33cr33','33cr33'),('53cr37','53cr37'),('secret','secret'),('Secret','Secret')]
openssl=r'C:\msys64\mingw64\bin\openssl.exe'
for label,password in candidates:
    p=subprocess.run([openssl,'enc','-d','-aes-256-cbc','-md','md5','-a','-A','-pass','pass:'+password],input=cipher_b64,capture_output=True)
    preview=p.stdout.decode('utf-8','replace')[:220]
    print(f'{label}: exit={p.returncode} bytes={len(p.stdout)} plaintext={preview!r}')
    if p.returncode==0:
        print('  SUCCESS_TEXT_REPR='+repr(p.stdout.decode('utf-8')))
        print('  SUCCESS_HEX='+p.stdout.hex())
print('jpeg_bytes',len(img),'jpeg_md5',hashlib.md5(img).hexdigest(),'jpeg_base64_md5',hashlib.md5(img_b64).hexdigest())
print('full_plain_bytes',len(full),'full_md5',hashlib.md5(full).hexdigest(),'full_base64_md5',hashlib.md5(full_b64).hexdigest())
positions=[i for i in range(len(full)-1) if full[i:i+2]==b'\xff\xd9']
print('jpeg_eoi_offsets',positions[-8:])
if positions:
    eoi=positions[-1]+2
    tail=full[eoi:]
    print('last_eoi_end',eoi,'tail_length',len(tail),'tail_head_hex',tail[:128].hex(),'tail_ascii',repr(tail[:128]))
example_input='012345678'+'Harmony5337'
print('example_flag_input',repr(example_input))
print('example_flag_md5',hashlib.md5(example_input.encode()).hexdigest())

