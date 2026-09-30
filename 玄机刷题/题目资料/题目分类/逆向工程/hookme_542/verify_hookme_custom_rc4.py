import zipfile,re,pathlib,hashlib
apk=pathlib.Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\hookme_542\附件解包\hookme\HookMe.apk')
package='com.example.hookme'
with zipfile.ZipFile(apk) as z: arsc=z.read('resources.arsc')
hexes=re.findall(rb'(?<![0-9A-Fa-f])([0-9A-Fa-f]{64,})(?![0-9A-Fa-f])',arsc)
if len(hexes)!=1:raise SystemExit(f'expected exactly one long hex string; found {len(hexes)}')
cipher=bytes.fromhex(hexes[0].decode())
key=package.encode('ascii')
seed=((key[0] if key[0]<128 else key[0]-256)<<8)|(key[1] if key[1]<128 else key[1]-256)
seed &= 0xffffffff
print('APK_SHA256',hashlib.sha256(apk.read_bytes()).hexdigest())
print('PACKAGE',package,'KEY_BYTES',key.hex(),'KEY_LEN',len(key),'SBOX_SEED',seed,hex(seed))
print('CIPHERTEXT_HEX',cipher.hex(),'LEN',len(cipher))
# std::mersenne_twister_engine<uint_fast32_t,32,624,397,31,0x9908b0df,11,0xffffffff,7,0x9d2c5680,15,0xefc60000,18,1812433253>
class MT19937:
 def __init__(self,seed):
  self.mt=[0]*624;self.mt[0]=seed&0xffffffff
  for i in range(1,624):
   x=self.mt[i-1]^(self.mt[i-1]>>30)
   self.mt[i]=(1812433253*x+i)&0xffffffff
  self.index=624
 def next(self):
  if self.index>=624:
   for i in range(624):
    y=(self.mt[i]&0x80000000)|(self.mt[(i+1)%624]&0x7fffffff)
    self.mt[i]=(self.mt[(i+397)%624]^(y>>1)^(0x9908b0df if y&1 else 0))&0xffffffff
   self.index=0
  y=self.mt[self.index];self.index+=1
  y^=y>>11;y^=(y<<7)&0x9d2c5680;y^=(y<<15)&0xefc60000;y^=y>>18
  return y&0xffffffff
mt=MT19937(seed)
init_s=[mt.next()&255 for _ in range(256)]
print('MT19937_FIRST8',[hex(x) for x in init_s[:8]])
def native_rc4(data,key):
 mt=MT19937(seed)
 s=[mt.next()&255 for _ in range(256)]
 j=0
 for i in range(256):
  # JNI input/key in this task are ASCII, so C++ signed char equals byte.
  j=(j+s[i]+key[i%len(key)])%256
  s[i],s[j]=s[j],s[i]
 out=bytearray();i=j=0
 for x in data:
  i=(i+1)%256;j=(j+s[i])%256;s[i],s[j]=s[j],s[i]
  out.append(x^s[(s[i]+s[j])%256])
 return bytes(out)
plain=native_rc4(cipher,key)
print('RECOVERED_BYTES',repr(plain))
try:print('RECOVERED_UTF8',plain.decode('utf-8'))
except UnicodeDecodeError as e:print('UTF8_ERROR',e)
reenc=native_rc4(plain,key)
print('REENCRYPT_HEX',reenc.hex())
print('REENCRYPT_MATCHES_RESOURCE',reenc==cipher)
print('FLAG_FORMAT',bool(re.fullmatch(rb'flag\{[^\r\n{}]+\}',plain,re.I)))
