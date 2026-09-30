from pathlib import Path
import dis, io, marshal, struct, types, zlib
root=Path(__file__).parent
exe=root/'game_flag.exe'
data=exe.read_bytes()
cookie_size=88
magic, package_len, toc_offset, toc_len, pyver, py_dll=struct.unpack('!8sIIII64s',data[-cookie_size:])
if magic != bytes.fromhex('4d45490c0b0a0b0e'):
    raise SystemExit('Unexpected PyInstaller cookie')
package_start=len(data)-package_len
toc=data[package_start+toc_offset:package_start+toc_offset+toc_len]
pos=0; found=None
while pos<len(toc):
    entry_size,offset,stored_len,original_len,compressed,type_code=struct.unpack('!iIIIBc',toc[pos:pos+18])
    name=toc[pos+18:pos+entry_size].split(b'\x00',1)[0].decode('utf-8','replace')
    if name=='game':
        raw=data[package_start+offset:package_start+offset+stored_len]
        found=zlib.decompress(raw) if compressed else raw
        break
    pos+=entry_size
if found is None:
    raise SystemExit('game entry not found')
(root/'game.marshal').write_bytes(found)
print('exe_sha256=',__import__('hashlib').sha256(data).hexdigest())
print('game_marshaled_bytes=',len(found),'first16=',found[:16].hex())
try:
    code=marshal.loads(found)
except Exception as exc:
    raise SystemExit(f'marshal.loads under this Python failed: {exc!r}')
if not isinstance(code,types.CodeType):
    raise SystemExit(f'Unexpected marshal object: {type(code)}')
print('module_code_name=',code.co_name,'firstlineno=',code.co_firstlineno,'constants=',len(code.co_consts),'names=',code.co_names)
out=io.StringIO()
def walk(obj,depth=0):
    if not isinstance(obj,types.CodeType): return
    print('\n'+'='*20+' '*depth+' CODE '+obj.co_name+' line '+str(obj.co_firstlineno)+' '+'='*20,file=out)
    print('co_names=',obj.co_names,file=out)
    print('co_varnames=',obj.co_varnames,file=out)
    print('co_consts=',repr(obj.co_consts),file=out)
    dis.dis(obj,file=out)
    for value in obj.co_consts:
        if isinstance(value,types.CodeType): walk(value,depth+1)
walk(code)
text=out.getvalue()
(root/'game_disassembly.txt').write_text(text,encoding='utf-8')
print('disassembly_chars=',len(text),'saved=',root/'game_disassembly.txt')
print('file_operations_in_code_names=',[name for name in code.co_names if any(term in name.lower() for term in ('open','read','hash','md5','flag'))])
