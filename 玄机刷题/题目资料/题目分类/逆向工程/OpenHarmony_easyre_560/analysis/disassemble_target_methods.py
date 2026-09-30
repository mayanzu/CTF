import re,struct,sys,yaml
from pathlib import Path
b=Path(sys.argv[1]).read_bytes(); isa=yaml.safe_load(open(sys.argv[2],encoding='utf-8'))
def uleb(p):
    value=0; shift=0
    while True:
        x=b[p]; p+=1; value|=(x&0x7f)<<shift
        if not x&0x80: return value,p
        shift+=7

def string(off):
    tagged,p=uleb(off); end=b.index(0,p); return b[p:end].decode('utf-8','replace')

def method_tags(p):
    code=debug=None
    while True:
        tag=b[p]; p+=1
        if tag==0: return p,code,debug
        if tag==1: code=struct.unpack_from('<I',b,p)[0]; p+=4
        elif tag==2: p+=1
        else:
            v=struct.unpack_from('<I',b,p)[0]; p+=4
            if tag==5: debug=v

def class_tags(p):
    while True:
        tag=b[p]; p+=1
        if tag==0: return p
        if tag==1: n,p=uleb(p); p+=2*n
        elif tag==2: p+=1
        else: p+=4

def field_tags(p):
    while True:
        tag=b[p]; p+=1
        if tag==0: return p
        if tag==1: _,p=uleb(p)
        else: p+=4

def load_methods():
    result=[]; n=struct.unpack_from('<I',b,0x1c)[0]; idx=struct.unpack_from('<I',b,0x20)[0]
    for ci in range(n):
        off=struct.unpack_from('<I',b,idx+4*ci)[0]; cls,p=string(off),off
        tag,p=uleb(p); p=b.index(0,p)+1; p+=4
        _,p=uleb(p); nf,p=uleb(p); nm,p=uleb(p); p=class_tags(p)
        for _ in range(nf):
            no=struct.unpack_from('<I',b,p+4)[0]; p+=8; _,p=uleb(p); p=field_tags(p)
        for _ in range(nm):
            no=struct.unpack_from('<I',b,p+4)[0]; p+=8; _,p=uleb(p); p,code,debug=method_tags(p)
            result.append((cls,string(no),code,debug))
    return result

def build_map():
    ops={}; pref={x['name']:x['opcode_idx'] for x in isa['prefixes']}
    for group in isa['groups']:
        for ins in group.get('instructions',[]):
            oc=ins.get('opcode_idx',[]); fm=ins.get('format',[])
            if isinstance(oc,int): oc=[oc]
            if isinstance(fm,str): fm=[fm]
            for code,fmt in zip(oc,fm): ops[(ins.get('prefix'),code)]=(ins['sig'],fmt,ins.get('properties',[]))
    pref_rev={v:k for k,v in pref.items()}
    return ops,pref_rev

def resolve_string(codeoff, index):
    n=struct.unpack_from('<I',b,0x34)[0]; section=struct.unpack_from('<I',b,0x38)[0]
    for region in range(n):
        off=section+region*40
        start,end=struct.unpack_from('<II',b,off)
        if start <= codeoff < end:
            size,table=struct.unpack_from('<II',b,off+16)
            if index >= size: return f'<bad-string-index:{index:#x}/{size}>'
            string_off=struct.unpack_from('<I',b,table+index*4)[0]
            return repr(string(string_off))
    return f'<no-index-region:{codeoff:#x}>'

def decode(code, codeoff):
    ops,pref_rev=build_map(); pos=0; out=[]
    while pos<len(code):
        start=pos; op=code[pos]; pos+=1; prefix=pref_rev.get(op); op2=None
        if prefix is not None:
            if pos>=len(code): out.append(f'{start:04x}: <truncated prefix {op:#x}>'); break
            op2=code[pos]; pos+=1; key=(prefix,op2)
        else: key=(None,op)
        if key not in ops:
            out.append(f'{start:04x}: db 0x{op:02x}'+(f' 0x{op2:02x}' if op2 is not None else '')); continue
        sig,fmt,props=ops[key]
        spec=fmt.removeprefix('pref_').removeprefix('op_')
        tokens=re.findall(r'([A-Za-z]+\d*)_(\d+)',spec)
        args=[]
        j=0
        while j<len(tokens):
            name,width=tokens[j][0],int(tokens[j][1]); width_bytes=(width+7)//8
            if width==4:
                value=code[pos]; pos+=1
                # Packed operands are emitted most-significant nibble first in assembly format.
                if j+1<len(tokens) and int(tokens[j+1][1])==4:
                    args.extend([f'{name}={(value>>4)&15}',f'{tokens[j+1][0]}={value&15}']); j+=2; continue
                args.append(f'{name}={value&15}')
            else:
                raw=int.from_bytes(code[pos:pos+width_bytes],'little',signed=False); pos+=width_bytes
                signed=(':'+ 'i' in sig) and (f'{name}:' in sig)
                if signed and raw&(1<<(width-1)): raw-=1<<width
                if name.startswith('id') and ('string_id' in sig or 'literalarray_id' in sig):
                    args.append(f'{name}={raw:#x}->{resolve_string(codeoff,raw)}')
                else:
                    args.append(f'{name}={raw:#x}' if name.startswith('id') else f'{name}={raw}')
            j+=1
        if pos<=start: raise RuntimeError('decoder stalled')
        out.append(f'{start:04x}: {sig}'+(' '+', '.join(args) if args else '')+f'    [{code[start:pos].hex(" ")}]')
    return out

methods=load_methods()
for cls,name,codeoff,debug in methods:
    if codeoff is None or not any(k in cls for k in ('pages/Flag','pages/Index','utils/Coder')): continue
    p=codeoff; nv,p=uleb(p); na,p=uleb(p); size,p=uleb(p); tries,p=uleb(p); code=b[p:p+size]
    print(f'\nMETHOD {cls}::{name} code_off={codeoff:#x} debug={debug:#x} vregs={nv} args={na} size={size} tries={tries}')
    for line in decode(code,codeoff): print(line)
