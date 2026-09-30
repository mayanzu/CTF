"""Parse PE layout and map printable string file offsets to virtual addresses."""
from __future__ import annotations
import pathlib, re, struct

ROOT = pathlib.Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\Base_543")
EXE = ROOT / "analysis" / "unpacked" / "你知道Base么" / "你知道Base么.exe"
DISASM = ROOT / "analysis" / "objdump_disassembly_intel_ascii.txt"
OUT = ROOT / "analysis" / "pe_layout_string_map.txt"
b = EXE.read_bytes()
peoff = struct.unpack_from("<I", b, 0x3C)[0]
assert b[peoff:peoff+4] == b"PE\0\0"
machine, nsects, ts, symptr, nsyms, opt_size, chars = struct.unpack_from("<HHIIIHH", b, peoff+4)
opt = peoff + 24
magic = struct.unpack_from("<H", b, opt)[0]
assert magic == 0x20B, hex(magic)
imagebase = struct.unpack_from("<Q", b, opt+24)[0]
entry_rva = struct.unpack_from("<I", b, opt+16)[0]
secttab = opt + opt_size
sections = []
for i in range(nsects):
    o = secttab + 40*i
    name = b[o:o+8].split(b"\0",1)[0].decode("ascii","replace")
    vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", b, o+8)
    sections.append((name,vsize,va,rawsize,rawptr))
lines = [
    f"file_size={len(b)}",
    f"machine=0x{machine:04x} sections={nsects} timestamp=0x{ts:08x}",
    f"PE32+ imagebase=0x{imagebase:x} entry_rva=0x{entry_rva:x} entry_va=0x{imagebase+entry_rva:x}",
    "sections:",
]
for name,vsize,va,rawsize,rawptr in sections:
    lines.append(f"{name:8} RVA=0x{va:06x} VA=0x{imagebase+va:012x} vsize=0x{vsize:x} raw=0x{rawptr:x}+0x{rawsize:x}")
rdata = next(s for s in sections if s[0] == ".rdata")
_,vsize,va,rawsize,rawptr = rdata
blob = b[rawptr:rawptr+rawsize]
lines += ["", "ASCII strings in .rdata containing task-relevant terms:"]
term = re.compile(rb"(?i)(input|successful|failed|level|CTFer|key|table|flag|error|Base|%\d+s)")
for m in re.finditer(rb"[\x20-\x7e]{3,}", blob):
    s = m.group().decode("ascii","replace")
    if term.search(m.group()):
        off = rawptr + m.start()
        address = imagebase + va + (off-rawptr)
        lines.append(f"file=0x{off:06x} VA=0x{address:012x} len={len(s)} {s}")
disasm = DISASM.read_text(encoding="utf-8", errors="replace")
lines += ["", "Direct disassembly references to those string addresses:"]
for m in re.finditer(rb"[\x20-\x7e]{3,}", blob):
    s = m.group().decode("ascii","replace")
    if not term.search(m.group()):
        continue
    off=rawptr+m.start()
    address=imagebase+va+(off-rawptr)
    token=f"0x{address:x}"
    refs=[ln for ln in disasm.splitlines() if token.lower() in ln.lower()]
    lines.append(f"{token} {s!r}: {len(refs)} refs")
    lines.extend("  "+ln.strip() for ln in refs[:8])
OUT.write_text("\n".join(lines)+"\n",encoding="utf-8")
print("report="+str(OUT))
print("\n".join(lines))

