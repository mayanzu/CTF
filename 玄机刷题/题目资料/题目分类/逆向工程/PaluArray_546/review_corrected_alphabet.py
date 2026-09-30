from pathlib import Path
import hashlib,struct,sys
sys.stdout.reconfigure(encoding='utf-8',errors='backslashreplace')
p=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\PaluArray_546\PaluArray_flag_unpacked.exe')
b=p.read_bytes(); pe=struct.unpack_from('<I',b,0x3c)[0]; opt=pe+24; base=struct.unpack_from('<Q',b,opt+24)[0]; n=struct.unpack_from('<H',b,pe+6)[0]; st=opt+struct.unpack_from('<H',b,pe+20)[0]
for j in range(n):
 q=st+j*40; nm=b[q:q+8].split(b'\0',1)[0].decode('ascii','replace'); vs,rv,rs,rp=struct.unpack_from('<IIII',b,q+8)
 if rv<=0x5e66<rv+rs:
  off=rp+0x5e66-rv; raw=b[off:off+28]; break
else: raise RuntimeError('RVA not file-backed')
alpha=raw.decode('utf-16le').split('\0',1)[0]
target='1145141919810'
candidate=''.join(alpha[int(d)] for d in target)
forward=''.join(str(alpha.find(ch)) for ch in candidate)
print('file_sha256',hashlib.sha256(b).hexdigest())
print('RVA_0x5e66 raw bytes',raw.hex())
print('UTF16 alphabet from RVA 0x5e66',repr(alpha))
print('alphabet length',len(alpha),'indices',list(enumerate(alpha)))
print('target',target)
print('candidate',repr(candidate),'length',len(candidate))
print('re-encoded indices',forward,'exact_match',forward==target)
digest=hashlib.md5(candidate.encode('ascii')).hexdigest()
print('MD5 ASCII input',digest)
print('candidate flag',f'palu{{{digest}}}')
assert alpha=='gPalu_996!?'
assert forward==target
