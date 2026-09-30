"""Read PE metadata and imports without loading or executing the challenge binary."""
from pathlib import Path
import struct
import sys

path = Path(sys.argv[1])
b = path.read_bytes()
u16 = lambda off: struct.unpack_from("<H", b, off)[0]
u32 = lambda off: struct.unpack_from("<I", b, off)[0]
print(f"file={path} size={len(b)} bytes")
if b[:2] != b"MZ":
    raise SystemExit("missing MZ signature")
pe = u32(0x3C)
print(f"e_lfanew=0x{pe:x} signature={b[pe:pe+4]!r}")
if b[pe:pe+4] != b"PE\0\0":
    raise SystemExit("missing PE signature")
coff = pe + 4
machine, nsec, timestamp, symptr, nsym, optsize, chars = struct.unpack_from("<HHIIIHH", b, coff)
opt = coff + 20
magic = u16(opt)
bits = {0x10B: 32, 0x20B: 64}.get(magic, 0)
if not bits:
    raise SystemExit(f"unknown optional-header magic 0x{magic:x}")
ep = u32(opt + 16)
imagebase = u32(opt + 28) if bits == 32 else struct.unpack_from("<Q", b, opt + 24)[0]
subsystem = u16(opt + 68)
ndir_off = opt + (92 if bits == 32 else 108)
ndir = u32(ndir_off)
dirs_off = opt + (96 if bits == 32 else 112)
print(f"machine=0x{machine:04x} bits={bits} sections={nsec} timestamp=0x{timestamp:08x}")
print(f"optional_magic=0x{magic:04x} imagebase=0x{imagebase:x} entry_rva=0x{ep:x} entry_va=0x{imagebase+ep:x} subsystem={subsystem} chars=0x{chars:04x}")
sections = []
shoff = opt + optsize
for i in range(nsec):
    off = shoff + i * 40
    name = b[off:off+8].split(b"\0", 1)[0].decode("ascii", "replace")
    vsize, va, rsize, rptr = struct.unpack_from("<IIII", b, off + 8)
    flags = u32(off + 36)
    sections.append((name, vsize, va, rsize, rptr, flags))
    print(f"section[{i}] {name!r} VA=0x{va:x} VS=0x{vsize:x} RAW=0x{rsize:x} PTR=0x{rptr:x} FLAGS=0x{flags:08x}")

def rva_to_offset(rva):
    if rva < u32(opt + 60):
        return rva
    for name, vsize, va, rsize, rptr, flags in sections:
        if va <= rva < va + max(vsize, rsize):
            delta = rva - va
            if delta >= rsize:
                raise ValueError(f"RVA 0x{rva:x} is in zero-fill tail of {name}")
            return rptr + delta
    raise ValueError(f"unmapped RVA 0x{rva:x}")

for index, label in ((1, "IMPORT"), (5, "BASERELOC"), (6, "DEBUG"), (10, "LOAD_CONFIG"), (12, "IAT")):
    if index >= ndir:
        continue
    rva, size = struct.unpack_from("<II", b, dirs_off + index * 8)
    print(f"directory[{index}] {label} RVA=0x{rva:x} SIZE=0x{size:x}")
    if index == 1 and rva:
        pos = rva_to_offset(rva)
        stride = 20 if bits == 32 else 20
        while pos + stride <= len(b):
            oft, stamp, chain, name_rva, ft = struct.unpack_from("<IIIII", b, pos)
            if not any((oft, stamp, chain, name_rva, ft)):
                break
            name_off = rva_to_offset(name_rva)
            dll = b[name_off:b.find(b"\0", name_off)].decode("ascii", "replace")
            print(f"  DLL {dll!r} OFT=0x{oft:x} FT=0x{ft:x}")
            thunk_rva = oft or ft
            width = bits // 8
            thunk_off = rva_to_offset(thunk_rva)
            while thunk_off + width <= len(b):
                thunk = int.from_bytes(b[thunk_off:thunk_off+width], "little")
                if not thunk:
                    break
                ordinal_mask = 1 << (bits - 1)
                if thunk & ordinal_mask:
                    print(f"    ordinal #{thunk & 0xffff}")
                else:
                    hint_name = rva_to_offset(thunk)
                    hint = u16(hint_name)
                    end = b.find(b"\0", hint_name + 2)
                    function = b[hint_name+2:end].decode("ascii", "replace")
                    print(f"    {function} (hint={hint})")
                thunk_off += width
            pos += stride

try:
    ep_off = rva_to_offset(ep)
    print(f"entry_file_offset=0x{ep_off:x} bytes={b[ep_off:ep_off+64].hex(' ')}")
except Exception as e:
    print(f"entry_file_offset_error={e}")
