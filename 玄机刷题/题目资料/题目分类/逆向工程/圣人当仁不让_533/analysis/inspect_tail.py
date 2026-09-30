from pathlib import Path
import base64
p=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\圣人当仁不让_533\analysis\ez_vm.exe')
b=p.read_bytes()
for start,end in [(0x8c40,0x8cd0),(0x8c00,0x8cc0)]:
 print(f'file[{start:#x}:{end:#x}]',repr(b[start:end]))
 for i in range(start,end):
  if b[i:i+1] == b'\0': continue
# emulate the exact operation established by disassembly
def transform(x):return bytes((((c^0xaa)+3)&255) for c in x)
def bug_b64(data):
 out=base64.b64encode(data).decode()
 pad=(len(out)-(len(data)%3))&3
 return out[:len(out)-pad]+'='*pad
for candidate in [b'flag{a1e05109-4xT',b'flag{a1e05109-4xU',b'flag{a1e05109-4xW',b'flag{a1e05109-4x}']:
 enc=bug_b64(transform(candidate))
 print('candidate',repr(candidate),'len',len(candidate),'transform',transform(candidate).hex(),'encoded',enc,'target_match',enc=='z8nO0NTOntKdop6dloqh1Q==')
