from pathlib import Path
import struct, sys

class Code:
    def __init__(self, fields): self.fields=fields
    def __repr__(self): return f"<Code {self.fields.get('name')!r} at line {self.fields.get('firstlineno')}>"

class Reader:
    def __init__(self,b): self.b=b; self.p=0; self.refs=[]
    def take(self,n):
        if n<0 or self.p+n>len(self.b): raise ValueError(f"truncated at {self.p}, need {n}")
        x=self.b[self.p:self.p+n]; self.p+=n; return x
    def i32(self): return struct.unpack("<i",self.take(4))[0]
    def u32(self): return struct.unpack("<I",self.take(4))[0]
    def obj(self):
        t=self.take(1)[0]; ref=bool(t&0x80); t&=0x7f; slot=None
        if ref: slot=len(self.refs); self.refs.append(None)
        ch=chr(t)
        if ch=="N": v=None
        elif ch=="F": v=False
        elif ch=="T": v=True
        elif ch=="S": v=StopIteration
        elif ch==".": v=Ellipsis
        elif ch=="i": v=self.i32()
        elif ch=="I": v=struct.unpack("<q",self.take(8))[0]
        elif ch=="l":
            nd=self.i32(); sign=-1 if nd<0 else 1; n=abs(nd); acc=0
            for j in range(n): acc |= self.take(2)[0] << (15*j) | self.take(1)[0] << (15*j+8)
            v=sign*acc
        elif ch in ("s","t"):
            n=self.i32(); raw=self.take(n); v=raw if ch=="s" else raw.decode("utf-8","surrogatepass")
        elif ch=="u":
            n=self.i32(); v=self.take(n).decode("utf-8","surrogatepass")
        elif ch in ("a","A"):
            n=self.i32(); raw=self.take(n); v=raw.decode("ascii","replace")
        elif ch in ("z","Z"):
            n=self.take(1)[0]; raw=self.take(n); v=raw.decode("ascii","replace")
        elif ch in ("f","g"):
            if ch=="f": n=self.take(1)[0]; v=float(self.take(n).decode())
            else: v=struct.unpack("<d",self.take(8))[0]
        elif ch=="x":
            n=self.take(1)[0]; a=float(self.take(n).decode()); n=self.take(1)[0]; b=float(self.take(n).decode()); v=complex(a,b)
        elif ch=="y":
            a,b=struct.unpack("<dd",self.take(16)); v=complex(a,b)
        elif ch=="r":
            idx=self.i32()
            if idx<0 or idx>=len(self.refs): raise ValueError(f"bad marshal ref {idx}")
            v=self.refs[idx]
        elif ch in ("(","[","<",">"):
            n=self.i32(); vals=[self.obj() for _ in range(n)]
            v=tuple(vals) if ch=="(" else (set(vals) if ch=="<" else frozenset(vals) if ch==">" else vals)
        elif ch==")":
            n=self.take(1)[0]; v=tuple(self.obj() for _ in range(n))
        elif ch=="{":
            d={}
            while True:
                if self.p>=len(self.b): raise ValueError("unterminated dict")
                if self.b[self.p]==0: self.p+=1; break
                k=self.obj(); val=self.obj(); d[k]=val
            v=d
        elif ch=="c":
            slot_for_code=slot
            nums=[self.i32() for _ in range(6)]
            code=self.obj(); consts=self.obj(); names=self.obj(); varnames=self.obj(); freevars=self.obj(); cellvars=self.obj()
            filename=self.obj(); name=self.obj(); firstlineno=self.i32(); lnotab=self.obj()
            v=Code(dict(zip(("argcount","posonlyargcount","kwonlyargcount","nlocals","stacksize","flags"),nums)) | {
                "code":code,"consts":consts,"names":names,"varnames":varnames,"freevars":freevars,"cellvars":cellvars,
                "filename":filename,"name":name,"firstlineno":firstlineno,"lnotab":lnotab})
        else: raise ValueError(f"unknown marshal type {ch!r} (0x{t:02x}) at {self.p-1:#x}")
        if ref: self.refs[slot]=v
        return v

def show(v, indent=0):
    if isinstance(v,Code):
        f=v.fields; pad=" "*indent
        print(f"{pad}CODE name={f['name']!r} filename={f['filename']!r} line={f['firstlineno']}; args={f['argcount']},locals={f['nlocals']},flags={f['flags']:#x}")
        print(f"{pad}  names={f['names']!r}")
        print(f"{pad}  varnames={f['varnames']!r}; freevars={f['freevars']!r}; cellvars={f['cellvars']!r}")
        print(f"{pad}  consts:")
        for i,c in enumerate(f['consts']):
            if isinstance(c,Code): print(f"{pad}    {i}:"); show(c,indent+6)
            else: print(f"{pad}    {i}: {c!r}")
        code=f['code']
        if isinstance(code,bytes):
            print(f"{pad}  bytecode ({len(code)} bytes):")
            for i in range(0,len(code),2):
                if i+1<len(code): print(f"{pad}    {i:04x}: op={code[i]:3d} arg={code[i+1]:3d}")
                else: print(f"{pad}    {i:04x}: op={code[i]:3d} trailing={code[i+1]:02x}")
        print(f"{pad}  lnotab={f['lnotab']!r}")
    elif isinstance(v,(tuple,list)):
        for c in v: show(c,indent)
    else: print(repr(v))

p=Path(sys.argv[1]); b=p.read_bytes()
r=Reader(b); obj=r.obj()
print(f"payload bytes={len(b)} parsed through={r.p} trailing={len(b)-r.p}; marshal refs={len(r.refs)}")
show(obj)