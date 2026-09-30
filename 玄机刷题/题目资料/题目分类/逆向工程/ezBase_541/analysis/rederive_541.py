"""Fresh offline static reconstruction of #541 from the original PE attachment.

This script never loads or executes ezre.exe. It parses the PE, models the NRV2B
bitstream used by the entry stub, applies the UPX relative-branch filter, then
recovers the unique 36-byte input satisfying the embedded transform.
"""
from __future__ import annotations
from pathlib import Path
import hashlib, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM
from capstone.x86 import X86_REG_RIP, X86_REG_RSI

ROOT = Path(__file__).resolve().parents[1]
ANALYSIS = ROOT / "analysis"
RAR = ROOT / "附件_平台原件" / "ezBase_platform_20260929.rar"
EXE = ROOT / "ezBase" / "ezre.exe"
OUT = ANALYSIS / "rederived_541_patched.bin"
ASM = ANALYSIS / "rederived_assembly.txt"
MASK32 = 0xffffffff


def sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest().upper()


def read_pe(path: Path):
    b = path.read_bytes()
    if b[:2] != b"MZ": raise ValueError("missing DOS signature")
    pe = struct.unpack_from("<I", b, 0x3c)[0]
    if b[pe:pe+4] != b"PE\0\0": raise ValueError("missing PE signature")
    machine, nsec, stamp, symptr, nsym, optsz, chars = struct.unpack_from("<HHIIIHH", b, pe+4)
    opt = pe + 24
    magic = struct.unpack_from("<H", b, opt)[0]
    if magic != 0x20b: raise ValueError(f"expected PE32+, got 0x{magic:x}")
    imagebase = struct.unpack_from("<Q", b, opt+24)[0]
    entry_rva = struct.unpack_from("<I", b, opt+16)[0]
    shoff = opt + optsz
    sections = []
    for i in range(nsec):
        off = shoff + i*40
        name = b[off:off+8].split(b"\0",1)[0].decode("ascii", "replace")
        vsz, va, rawsz, raw = struct.unpack_from("<IIII", b, off+8)
        sections.append((name,vsz,va,rawsz,raw))
    return b, imagebase, entry_rva, sections


def rva_to_raw(rva, sections):
    for name, vsz, va, rawsz, raw in sections:
        if va <= rva < va + max(vsz,rawsz):
            d = rva - va
            if d >= rawsz: raise ValueError(f"RVA 0x{rva:x} lies in zero-fill tail of {name}")
            return raw+d, name
    raise ValueError(f"RVA 0x{rva:x} has no raw mapping")


class BitReader:
    """ADD/ADC bit extraction as visible in the packed entry stub."""
    def __init__(self, data, pos): self.data, self.pos, self.buf = data, pos, 0
    def get(self):
        shifted = (self.buf << 1) & MASK32
        carry = (self.buf >> 31) & 1
        if shifted == 0:
            if self.pos+4 > len(self.data): raise EOFError(f"bit word at 0x{self.pos:x}")
            word = struct.unpack_from("<I", self.data, self.pos)[0]
            self.pos += 4
            carry = word >> 31
            self.buf = ((word << 1) | 1) & MASK32
        else:
            self.buf = shifted
        return carry
    def byte(self):
        if self.pos >= len(self.data): raise EOFError(f"literal at 0x{self.pos:x}")
        x = self.data[self.pos]; self.pos += 1; return x


def unpack_nrv2b(data, start):
    bits = BitReader(data, start)
    out = bytearray(); previous = 1; literal_count = match_count = 0
    while True:
        while bits.get():
            out.append(bits.byte()); literal_count += 1
            if len(out) > 0x100000: raise ValueError("NRV2B output limit reached")
        code = 1
        while True:
            code = ((code << 1) | bits.get()) & MASK32
            if bits.get(): break
        if code == 2:
            distance = previous
        else:
            value = ((((code-3) & MASK32) << 8) | bits.byte()) & MASK32
            if value == MASK32:
                return bytes(out), bits.pos, literal_count, match_count
            distance = value + 1
            previous = distance
        short = (bits.get() << 1) | bits.get()
        if short:
            length = short + 1
        else:
            value = 1
            while True:
                value = ((value << 1) | bits.get()) & MASK32
                if bits.get(): break
            length = value + 3
        if distance > 0xd00: length += 1
        if distance < 1 or distance > len(out):
            raise ValueError(f"invalid backref distance={distance}, decoded={len(out)}")
        for _ in range(length): out.append(out[-distance])
        match_count += 1
        if len(out) > 0x100000: raise ValueError("NRV2B output limit reached")


def patch_upx_filter(decoded, imagebase, section_rva=0x1000):
    """Model E8/E9 and near-Jcc fixups described by the packed stub."""
    b = bytearray(decoded); end = min(0x2a00-3, len(b)); i=0; edits=[]
    lowbase = (imagebase + section_rva) & MASK32
    while i < end:
        op=b[i]
        jcc = 0x80 <= op <= 0x8f and i > 0 and b[i-1] == 0x0f
        if op in (0xe8,0xe9) or jcc:
            operand=i+1
            if operand+4 > len(b): break
            if b[operand] == 0:
                old=int.from_bytes(b[operand:operand+4],"little")
                big=int.from_bytes(b[operand:operand+4],"big")
                op_addr=(lowbase+operand)&MASK32
                new=(big-op_addr+lowbase)&MASK32
                b[operand:operand+4]=new.to_bytes(4,"little")
                edits.append((i,operand,old,new))
            i=operand+4
        else: i+=1
    return bytes(b), edits


def disassemble(img, ranges):
    md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
    lines=[]
    for start,size,label in ranges:
        lines.append(f"--- {label}: output offset 0x{start:x} ---")
        for ins in md.disasm(img[start:start+size], 0x140001000+start):
            lines.append(f"{ins.address:016x}: {ins.bytes.hex(' '):<40} {ins.mnemonic:<8} {ins.op_str}")
    return "\n".join(lines)+"\n"


def cstr(buf, offset):
    end=buf.find(b"\0",offset)
    if end<0: raise ValueError(f"unterminated string at 0x{offset:x}")
    return buf[offset:end]


rarbytes=RAR.read_bytes(); raw, imagebase, entry_rva, sections=read_pe(EXE)
print(f"original_rar_name={RAR.name}")
print(f"rar_size={len(rarbytes)} rar_sha256={sha256(rarbytes)}")
print(f"executable_relative=ezBase/ezre.exe")
print(f"exe_size={len(raw)} exe_sha256={sha256(raw)}")
print(f"imagebase=0x{imagebase:x} entry_rva=0x{entry_rva:x}")
for name,vsz,va,rawsz,ptr in sections:
    print(f"section={name} RVA=0x{va:x} VSZ=0x{vsz:x} RAW=0x{rawsz:x} PTR=0x{ptr:x}")
entry_off, entry_sec=rva_to_raw(entry_rva,sections)
print(f"entry_raw_offset=0x{entry_off:x} section={entry_sec}")

# Static decode: entry stub's first RIP-relative LEA into RSI identifies the packed stream.
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
stub=raw[entry_off:entry_off+0x300]
stream_rva=None
for ins in md.disasm(stub,imagebase+entry_rva):
    if ins.mnemonic=="lea" and ins.operands and ins.operands[0].type==1 and ins.operands[0].reg==X86_REG_RSI:
        mem=ins.operands[1]
        if mem.type==CS_OP_MEM and mem.mem.base==X86_REG_RIP:
            stream_va=ins.address+ins.size+mem.mem.disp
            stream_rva=stream_va-imagebase
            print(f"stub_stream_pointer_instruction=0x{ins.address:x}: {ins.mnemonic} {ins.op_str}")
            print(f"compressed_stream_va=0x{stream_va:x} rva=0x{stream_rva:x}")
            break
if stream_rva is None:
    raise RuntimeError("could not statically identify entry stub's RSI source LEA")
stream_off, stream_section=rva_to_raw(stream_rva,sections)
print(f"compressed_stream_raw_offset=0x{stream_off:x} section={stream_section}")

# Keep the stub instruction bytes as evidence for the chosen decompressor model.
print("entry_stub_disassembly:")
for ins in list(md.disasm(stub,imagebase+entry_rva))[:36]:
    print(f"  {ins.address:016x}: {ins.bytes.hex(' '):<40} {ins.mnemonic:<8} {ins.op_str}")

decoded, consumed_end, literals, matches=unpack_nrv2b(raw,stream_off)
print(f"nrv2b_end_marker=observed")
print(f"compressed_stream_end_raw_offset=0x{consumed_end:x} consumed={consumed_end-stream_off}")
print(f"decoded_size=0x{len(decoded):x} ({len(decoded)}) literals={literals} matches={matches}")
print(f"decoded_sha256={sha256(decoded)}")
patched, edits=patch_upx_filter(decoded,imagebase)
print(f"upx_filter_edits={len(edits)}")
print(f"patched_sha256={sha256(patched)}")
OUT.write_bytes(patched)
print(f"patched_output_relative=analysis\{OUT.name}")

# The entry code explicitly gates on 36 input bytes; target and table are RIP data references.
target=cstr(patched,0x3000); alphabet=cstr(patched,0x3040)
print(f"target_offset=0x3000 target_len={len(target)} target={target.decode('ascii')}")
print(f"alphabet_offset=0x3040 alphabet_len={len(alphabet)} alphabet={alphabet.decode('ascii')}")
print(f"main_length_gate_bytes={patched[0x89:0x90].hex(' ')} (cmp qword [rsp+0x30], 0x24)")

if len(target)!=48 or len(alphabet)!=64: raise ValueError("embedded data lengths differ from expected code references")
# Candidate length 36 is a multiple of three, so all 48 encoder output bytes are non-padding.
# For each transformed byte, invert the conditional XOR and custom alphabet index.
prexor=bytes(ch ^ 0x04 for ch in target)
if any(ch not in alphabet for ch in prexor):
    bad=[(i,ch,ch^4) for i,ch in enumerate(target) if (ch^4) not in alphabet]
    raise ValueError(f"target does not invert to alphabet for 36-byte case: {bad}")
indices=[alphabet.index(ch) for ch in prexor]
recovered=bytearray()
for i in range(0,len(indices),4):
    a,b,c,d=indices[i:i+4]
    recovered.extend(((a<<2)|(b>>4), ((b&15)<<4)|(c>>2), ((c&3)<<6)|d))

# Encode with the decoded 64-byte map and model the conditional XOR from the actual code.
def forward(data):
    out=bytearray()
    for pos in range(0,len(data),3):
        q=data[pos:pos+3]
        v=(q[0]<<16)|(q[1]<<8)|q[2]
        chars=(alphabet[(v>>18)&63],alphabet[(v>>12)&63],alphabet[(v>>6)&63],alphabet[v&63])
        out.extend(x if x==ord('=') else x^4 for x in chars)
    return bytes(out)

print(f"inversion_pre_xor={prexor.decode('ascii')}")
print(f"unique_recovered_len={len(recovered)} bytes hex={recovered.hex()}")
print(f"recovered_candidate={recovered.decode('ascii')}")
print(f"length_gate_match={len(recovered)==0x24}")
print(f"fresh_forward_match={forward(recovered)==target}")
print(f"fresh_forward={forward(recovered).decode('ascii')}")

# One ambiguity exists only when a transformed '=' is interpreted as literal padding.
# Show it explicitly and reject it against the observed 36-byte length gate.
if target.endswith(b"="):
    padded_source=bytearray(prexor); padded_source[-1]=ord("=")
    if all(ch in alphabet or ch==ord("=") for ch in padded_source):
        padded_decoded=bytearray()
        vals=[alphabet.index(ch) if ch!=ord("=") else 0 for ch in padded_source]
        for i in range(0,len(vals),4):
            a,b,c,d=vals[i:i+4]
            padded_decoded.append((a<<2)|(b>>4))
            if padded_source[i+2]!=ord("="): padded_decoded.append(((b&15)<<4)|(c>>2))
            if padded_source[i+3]!=ord("="): padded_decoded.append(((c&3)<<6)|d)
        print(f"padding_interpretation_candidate_len={len(padded_decoded)} passes_0x24_gate={len(padded_decoded)==0x24}")

asm=disassemble(patched,[(0,0x150,"main and encoder call"),(0x320,0x80,"post-encode conditional XOR"),(0x2990,0x50,"comparison routine entry")])
ASM.write_text(asm,encoding="utf-8")
print(f"core_disassembly_relative=analysis\{ASM.name}")
if len(recovered)!=0x24 or forward(recovered)!=target:
    raise SystemExit("local candidate does not satisfy observed gate and transform")
