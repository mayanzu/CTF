from pathlib import Path
import hashlib
p=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\第一届启航杯checker_562\analysis\extracted\checker.exe')
b=p.read_bytes()
# Target address recovered from the main-function reference and PE .data section mapping.
imagebase=0x400000; target_va=0x404020; target_rva=target_va-imagebase
# .data: RVA 0x4000, raw ptr 0x3200.
off=0x3200+(target_rva-0x4000)
end=b.index(b'\0',off)
target=b[off:end]
candidate=bytes(x^0x23 for x in target)
encoded=bytes(x^0x23 for x in candidate)
print('input PE SHA256:',hashlib.sha256(b).hexdigest().upper())
print(f'target VA=0x{target_va:x}, RVA=0x{target_rva:x}, raw offset=0x{off:x}')
print('encrypted NUL-terminated buffer length:',len(target))
print('encrypted bytes:',target.hex())
print('candidate repr:',repr(candidate))
print('candidate ascii:',candidate.decode('ascii','strict'))
print('candidate length:',len(candidate))
print('forward XOR output:',encoded.hex())
print('target match:',encoded==target)
print('format check:',candidate.startswith(b'flag{') and candidate.endswith(b'}'))
assert encoded==target
assert candidate.startswith(b'flag{') and candidate.endswith(b'}')
