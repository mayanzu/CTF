from pathlib import Path
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP, X86_OP_IMM

path = Path(sys.argv[1])
data = path.read_bytes()
pe = struct.unpack_from("<I", data, 0x3C)[0]
opt = pe + 24
entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
image_base = struct.unpack_from("<Q", data, opt + 24)[0]
num_sections = struct.unpack_from("<H", data, pe + 6)[0]
opt_size = struct.unpack_from("<H", data, pe + 20)[0]
section_table = opt + opt_size
sections = []
for i in range(num_sections):
    off = section_table + i*40
    name = data[off:off+8].split(b"\0",1)[0].decode("ascii","replace")
    vsize, rva, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off+8)
    flags = struct.unpack_from("<I", data, off+36)[0]
    sections.append((name,vsize,rva,raw_size,raw_ptr,flags))
    print(f"section={name} rva=0x{rva:x} vsize=0x{vsize:x} raw=0x{raw_ptr:x}+0x{raw_size:x} flags=0x{flags:x}")
print(f"entry_rva=0x{entry_rva:x} entry_va=0x{image_base+entry_rva:x}")
def fileoff_to_va(fo):
    for name,vs,rva,rs,rp,flags in sections:
        if rp <= fo < rp+rs: return image_base+rva+(fo-rp)
    return None

needles = ["gPalu_996!?", "flag", "palu{", "1145141919810", "Success", "Failed", "Input Flag:"]
targets = []
for s in needles:
    raw = s.encode("utf-16le") + b"\0\0"
    start=0
    while True:
        fo=data.find(raw,start)
        if fo<0: break
        va=fileoff_to_va(fo)
        print(f"string={s!r} file_offset=0x{fo:x} va={hex(va) if va else None}")
        if va: targets.append((s,va,va+len(raw)))
        start=fo+1
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
for name,vs,rva,rs,rp,flags in sections:
    if not (flags & 0x20000000) or rs==0: continue
    insns=list(md.disasm(data[rp:rp+rs],image_base+rva))
    hits=[]
    for ix,ins in enumerate(insns):
        refs=[]
        for op in ins.operands:
            if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP: refs.append(ins.address+ins.size+op.mem.disp)
            elif op.type==X86_OP_IMM: refs.append(op.imm)
        for s,a,b in targets:
            if any(a<=x<b for x in refs): hits.append((ix,s,a))
    print(f"--- {name} decoded={len(insns)} xrefs={len(hits)} ---")
    seen=set()
    for ix,s,a in hits:
        print(f"xref string={s!r} target=0x{a:x}")
        for j in range(max(0,ix-10),min(len(insns),ix+16)):
            if j in seen: continue
            seen.add(j); ins=insns[j]
            print(f"0x{ins.address:x}: {ins.mnemonic:<8} {ins.op_str}")
