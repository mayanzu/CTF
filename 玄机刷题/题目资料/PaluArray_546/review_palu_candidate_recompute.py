from pathlib import Path
import hashlib,struct,sys
sys.stdout.reconfigure(encoding='utf-8',errors='backslashreplace')
dir=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluArray_546')
paths=[dir/'PaluArray_flag.exe',dir/'PaluArray_flag_upx_names.exe',dir/'PaluArray_flag_unpacked.exe']
for p in paths:
 b=p.read_bytes(); print('FILE',p.name,'size',len(b),'sha256',hashlib.sha256(b).hexdigest(),'upx_signature_count',b.count(b'UPX!'))
 for s in ['Palu_996!?','1145141919810','palu{','0123456789abcdef']:
  w=s.encode('utf-16le');print('  UTF16',repr(s),'offsets',[hex(i) for i in range(len(b)) if b.startswith(w,i)][:8])
print('\nInput mapping and digest, calculated from inferred UI algorithm (not executing attachment)')
alphabet='Palu_996!?';target='1145141919810'
by_index={i:ch for i,ch in enumerate(alphabet)}
candidate=''.join(by_index[int(c)] for c in target)
transformed=''.join(str(alphabet.find(ch)) for ch in candidate)
raw=candidate.encode('ascii')
print('alphabet length',len(alphabet),'indices',[(i,ch) for i,ch in enumerate(alphabet)])
print('target',target,'candidate',repr(candidate),'length',len(candidate))
print('transformed',transformed,'equal_target',transformed==target)
print('raw bytes hex',raw.hex(),'raw bytes count',len(raw))
print('MD5(raw candidate)',hashlib.md5(raw).hexdigest())
print('MD5(UTF16LE candidate)',hashlib.md5(candidate.encode('utf-16le')).hexdigest())
print('MD5(transformed digits ASCII)',hashlib.md5(transformed.encode('ascii')).hexdigest())
print('Expected wrapper form inferred from code',f'palu{{{hashlib.md5(raw).hexdigest()}}}')
