from pathlib import Path
import struct

class Code:
    def __init__(self, fields): self.fields=fields
    def __repr__(self): return f"<Code {self.fields.get('name')!r}>"

class Reader:
    def __init__(self, data): self.data=data; self.pos=0; self.refs=[]
    def take(self, n):
        if n < 0 or self.pos+n > len(self.data): raise ValueError(f"truncated marshal at {self.pos}, need {n}")
        b=self.data[self.pos:self.pos+n]; self.pos+=n; return b
    def i32(self): return struct.unpack("<i",self.take(4))[0]
    def obj(self):
        t=self.take(1)[0]; hasref=bool(t&0x80); t &= 0x7f
        slot=len(self.refs) if hasref else None
        if hasref: self.refs.append(None)
        ch=chr(t)
        if ch=="N": v=None
        elif ch=="F": v=False
        elif ch=="T": v=True
        elif ch=="S": v=StopIteration
        elif ch==".": v=Ellipsis
        elif ch=="i": v=self.i32()
        elif ch=="I": v=struct.unpack("<q",self.take(8))[0]
        elif ch=="l":
            nd=self.i32(); sign=-1 if nd<0 else 1; value=0
            for j in range(abs(nd)): value |= (struct.unpack("<H",self.take(2))[0] & 0x7fff) << (15*j)
            v=sign*value
        elif ch in ("s","t"):
            n=self.i32(); raw=self.take(n); v=raw if ch=="s" else raw.decode("utf-8","surrogatepass")
        elif ch=="u":
            n=self.i32(); v=self.take(n).decode("utf-8","surrogatepass")
        elif ch in ("a","A"):
            n=self.i32(); v=self.take(n).decode("ascii","replace")
        elif ch in ("z","Z"):
            n=self.take(1)[0]; v=self.take(n).decode("ascii","replace")
        elif ch in ("f","g"):
            if ch=="f": n=self.take(1)[0]; v=float(self.take(n).decode("ascii"))
            else: v=struct.unpack("<d",self.take(8))[0]
        elif ch=="x":
            n=self.take(1)[0]; a=float(self.take(n).decode("ascii")); n=self.take(1)[0]; b=float(self.take(n).decode("ascii")); v=complex(a,b)
        elif ch=="y":
            a,b=struct.unpack("<dd",self.take(16)); v=complex(a,b)
        elif ch=="r":
            idx=self.i32()
            if not 0 <= idx < len(self.refs): raise ValueError(f"bad marshal ref {idx}")
            v=self.refs[idx]
        elif ch in ("(","[","<",">"):
            n=self.i32(); items=[self.obj() for _ in range(n)]
            v=tuple(items) if ch=="(" else set(items) if ch=="<" else frozenset(items) if ch==">" else items
        elif ch==")":
            n=self.take(1)[0]; v=tuple(self.obj() for _ in range(n))
        elif ch=="{":
            v={}
            while True:
                if self.pos>=len(self.data): raise ValueError("unterminated marshal dict")
                if self.data[self.pos]==0: self.pos+=1; break
                k=self.obj(); v[k]=self.obj()
        elif ch=="c":
            nums=[self.i32() for _ in range(6)]
            code=self.obj(); consts=self.obj(); names=self.obj(); varnames=self.obj(); freevars=self.obj(); cellvars=self.obj()
            filename=self.obj(); name=self.obj(); firstlineno=self.i32(); lnotab=self.obj()
            keys=("argcount","posonlyargcount","kwonlyargcount","nlocals","stacksize","flags")
            v=Code(dict(zip(keys,nums)) | {"code":code,"consts":consts,"names":names,"varnames":varnames,
               "freevars":freevars,"cellvars":cellvars,"filename":filename,"name":name,
               "firstlineno":firstlineno,"lnotab":lnotab})
        else: raise ValueError(f"unknown marshal tag {ch!r} ({t:#x}) at {self.pos-1:#x}")
        if hasref: self.refs[slot]=v
        return v

def parse_file(path):
    data=Path(path).read_bytes(); reader=Reader(data); obj=reader.obj()
    if reader.pos != len(data): raise ValueError(f"trailing marshal data: {len(data)-reader.pos} bytes")
    return obj