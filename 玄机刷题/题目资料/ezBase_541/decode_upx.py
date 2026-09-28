import pathlib, struct, hashlib, re
path=pathlib.Path(__file__).resolve().parent/"ezBase"/"ezre.exe"
data=path.read_bytes()
src_off=0x21d
max_output=0xb000
class Reader:
    def __init__(self, raw, pos): self.raw=raw; self.pos=pos; self.bb=0; self.refills=0
    def bit(self):
        carry=(self.bb>>31)&1
        self.bb=(self.bb<<1)&0xffffffff
        if self.bb==0:
            if self.pos+4>len(self.raw): raise EOFError("bit buffer ran past file")
            word=struct.unpack_from("<I",self.raw,self.pos)[0]
            self.pos+=4; self.refills+=1
            self.bb=((word<<1)|carry)&0xffffffff
            return (word>>31)&1
        return carry
    def byte(self):
        if self.pos>=len(self.raw): raise EOFError("literal ran past file")
        b=self.raw[self.pos]; self.pos+=1; return b
r=Reader(data,src_off); out=bytearray(); last_off=1; commands=0
try:
    while len(out)<max_output:
        commands+=1
        if r.bit():
            out.append(r.byte())
        else:
            m_off=1
            while True:
                m_off=(m_off<<1)|r.bit()
                if r.bit(): break
                if m_off>0x10000000: raise ValueError("offset code exploded")
            if m_off==2:
                off=last_off
            else:
                code=((m_off-3)<<8)|r.byte()
                if code==0xffffffff:
                    print("END marker at compressed_pos=",hex(r.pos),"output_len=",len(out))
                    break
                off=code+1; last_off=off
            m_len=(r.bit()<<1)|r.bit()
            if m_len==0:
                m_len=1
                while True:
                    m_len=(m_len<<1)|r.bit()
                    if r.bit(): break
                    if m_len>0x10000000: raise ValueError("length code exploded")
                m_len+=2
            if off>0xd00: m_len+=1
            if off<=0 or off>len(out): raise ValueError(f"bad back-reference off={off} outlen={len(out)} at command={commands}")
            for _ in range(m_len): out.append(out[-off])
except Exception as e:
    print("decoder_exception:",type(e).__name__,str(e))
print("source_sha256:",hashlib.sha256(data).hexdigest())
print("source_size:",len(data),"src_off:",hex(src_off),"compressed_pos:",hex(r.pos),"refills:",r.refills,"commands:",commands)
print("output_len:",len(out),"output_head_hex:",out[:64].hex())
print("output_head_ascii:",repr(bytes(out[:128])))
print("contains_input_prompt:",b"input your flag:" in out)
print("visible_strings:")
for m in re.finditer(rb"[ -~]{4,}",out):
    s=m.group().decode("ascii","replace")
    if any(x.lower() in s.lower() for x in ["flag","length","right","wrong","try","input","base","yes","must"]): print(hex(m.start()),repr(s))
print("output_sha256:",hashlib.sha256(out).hexdigest())
if len(out)>0x1000 and (out[:2]==b"MZ" or b"input your flag:" in out):
    outpath=pathlib.Path(__file__).resolve().parent/"unpacked.bin"
    outpath.write_bytes(out); print("wrote:",outpath)
