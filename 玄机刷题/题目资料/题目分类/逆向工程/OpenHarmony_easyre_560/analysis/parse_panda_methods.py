import struct,sys
from pathlib import Path
b=Path(sys.argv[1]).read_bytes()
def uleb(p):
    value=0; shift=0
    while True:
        x=b[p]; p+=1; value|=(x&0x7f)<<shift
        if not x&0x80: return value,p
        shift+=7

def string(off):
    tagged,p=uleb(off); length=tagged>>1; end=b.index(0,p)
    raw=b[p:end]
    return raw.decode('utf-8','replace'),end+1

def tagged_fields(p):
    while True:
        tag=b[p]; p+=1
        if tag==0: return p
        if tag==1: _,p=uleb(p)
        elif tag in (2,3,4,5,6): p+=4
        else: raise ValueError(f'unknown field tag {tag} at {p-1:#x}')

def tagged_class(p):
    while True:
        tag=b[p]; p+=1
        if tag==0: return p
        if tag==1:
            n,p=uleb(p); p+=n*2
        elif tag==2: p+=1
        elif tag in (3,4,5,6,7): p+=4
        else: raise ValueError(f'unknown class tag {tag} at {p-1:#x}')

def tagged_method(p):
    code=debug=None
    while True:
        tag=b[p]; p+=1
        if tag==0: return p,code,debug
        if tag==1: code=struct.unpack_from('<I',b,p)[0]; p+=4
        elif tag==2: p+=1
        elif tag in (3,4,5,6,7,8,9):
            value=struct.unpack_from('<I',b,p)[0]; p+=4
            if tag==5: debug=value
        else: raise ValueError(f'unknown method tag {tag} at {p-1:#x}')

num=struct.unpack_from('<I',b,0x1c)[0]; idx=struct.unpack_from('<I',b,0x20)[0]
print(f'ABC={Path(sys.argv[1]).resolve()} size={len(b)} classes={num} class_idx_off={idx:#x}')
for ci in range(num):
    off=struct.unpack_from('<I',b,idx+ci*4)[0]
    name,p=string(off); super_off=struct.unpack_from('<I',b,p)[0]; p+=4
    access,p=uleb(p); nf,p=uleb(p); nm,p=uleb(p); p=tagged_class(p)
    fields=[]
    for fi in range(nf):
        classidx,protoidx=struct.unpack_from('<HH',b,p); no=struct.unpack_from('<I',b,p+4)[0]; p+=8
        flags,p=uleb(p); p=tagged_fields(p); fname,_=string(no); fields.append(fname)
    methods=[]
    for mi in range(nm):
        classidx,protoidx=struct.unpack_from('<HH',b,p); no=struct.unpack_from('<I',b,p+4)[0]; p+=8
        flags,p=uleb(p); p,code,debug=tagged_method(p); mname,_=string(no)
        methods.append((mname,code,debug,protoidx,flags))
    print(f'CLASS[{ci}] off={off:#x} name={name!r} fields={fields} methods={len(methods)} end={p:#x}')
    for m in methods:
        if m[1] is not None or name.endswith(('/Index','/Flag','/Coder')):
            print(f'  method={m[0]!r} code={None if m[1] is None else hex(m[1])} debug={None if m[2] is None else hex(m[2])} proto={m[3]} flags={m[4]:#x}')
