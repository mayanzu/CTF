from pathlib import Path
import math, struct, sys

src = Path(sys.argv[1])
outdir = Path(sys.argv[2])
data = src.read_bytes()
if data[:2] != b"MZ":
    raise SystemExit("Not an MZ executable")
peoff = struct.unpack_from("<I", data, 0x3c)[0]
if data[peoff:peoff+4] != b"PE\0\0":
    raise SystemExit("Missing PE signature")
machine, nsects, timestamp, symptr, nsyms, optsize, coff_chars = struct.unpack_from("<HHIIIHH", data, peoff+4)
opt = peoff + 24
magic = struct.unpack_from("<H", data, opt)[0]
is64 = magic == 0x20b
if magic not in (0x10b, 0x20b):
    raise SystemExit(f"Unknown optional header magic {magic:#x}")
entry_rva = struct.unpack_from("<I", data, opt+16)[0]
imagebase = struct.unpack_from("<Q" if is64 else "<I", data, opt+(24 if is64 else 28))[0]
section_align, file_align = struct.unpack_from("<II", data, opt+32)
size_image, size_headers = struct.unpack_from("<II", data, opt+56)
subsystem, dllchars = struct.unpack_from("<HH", data, opt+68)
ndirs = struct.unpack_from("<I", data, opt+(108 if is64 else 92))[0]
diroff = opt+(112 if is64 else 96)
dirnames = ["EXPORT","IMPORT","RESOURCE","EXCEPTION","SECURITY","BASERELOC","DEBUG","ARCH","GLOBALPTR","TLS","LOAD_CONFIG","BOUND_IMPORT","IAT","DELAY_IMPORT","CLR","RESERVED"]
dirs = []
for i in range(min(ndirs, 16)):
    rva, size = struct.unpack_from("<II", data, diroff+i*8)
    dirs.append((dirnames[i], rva, size))
sects = []
shoff = opt + optsize
for i in range(nsects):
    raw = data[shoff+i*40:shoff+(i+1)*40]
    name = raw[:8].split(b"\0",1)[0].decode("ascii","replace")
    vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", raw, 8)
    chars = struct.unpack_from("<I", raw, 36)[0]
    sects.append((name, vsize, va, rawsize, rawptr, chars))

def entropy(blob):
    if not blob: return 0.0
    counts = [0]*256
    for b in blob: counts[b] += 1
    n = len(blob)
    return -sum((c/n)*math.log2(c/n) for c in counts if c)

def rva_to_off(rva):
    if rva < size_headers and rva < len(data): return rva
    for name,vsize,va,rawsize,rawptr,chars in sects:
        span = max(vsize, rawsize)
        if va <= rva < va+span:
            off = rawptr+(rva-va)
            return off if off < len(data) else None
    return None

def cstr(off, limit=512):
    if off is None or off >= len(data): return ""
    end = data.find(b"\0", off, min(len(data), off+limit))
    if end < 0: end = min(len(data), off+limit)
    return data[off:end].decode("ascii","replace")

def parse_imports():
    result = []
    entry = next((x for x in dirs if x[0] == "IMPORT"), None)
    if not entry or not entry[1]: return result
    off = rva_to_off(entry[1])
    if off is None: return result
    ptrsize = 8 if is64 else 4
    ordinal_mask = (1 << (ptrsize*8-1))
    for idx in range(4096):
        pos = off+20*idx
        if pos+20 > len(data): break
        oft,stamp,chain,name_rva,ft = struct.unpack_from("<IIIII", data, pos)
        if not (oft or stamp or chain or name_rva or ft): break
        dll = cstr(rva_to_off(name_rva))
        thunk_rva = oft or ft
        thunkoff = rva_to_off(thunk_rva)
        syms = []
        if thunkoff is not None:
            for j in range(10000):
                tp = thunkoff+j*ptrsize
                if tp+ptrsize > len(data): break
                val = struct.unpack_from("<Q" if is64 else "<I", data, tp)[0]
                if not val: break
                if val & ordinal_mask:
                    syms.append(f"ordinal:{val & 0xffff}")
                else:
                    hn = rva_to_off(val)
                    if hn is None: syms.append(f"bad-rva:{val:#x}")
                    else: syms.append(cstr(hn+2))
        result.append((dll, syms))
    return result

def ascii_strings(blob, minlen=4):
    buf = bytearray()
    for b in blob + b"\0":
        if 32 <= b <= 126:
            buf.append(b)
        else:
            if len(buf) >= minlen:
                yield buf.decode("ascii","replace")
            buf.clear()

def utf16_strings(blob, minlen=4):
    # Scan both byte alignments; only printable low bytes with zero high bytes.
    for align in (0,1):
        i=align
        while i+1 < len(blob):
            start=i
            chars=[]
            while i+1 < len(blob):
                lo,hi=blob[i],blob[i+1]
                if 32 <= lo <= 126 and hi == 0:
                    chars.append(chr(lo)); i+=2
                else: break
            if len(chars) >= minlen: yield "".join(chars)
            i=max(i+2,start+2)

outdir.mkdir(parents=True, exist_ok=True)
imp = parse_imports()
imp_lines=[]
for dll, syms in imp:
    imp_lines.append(f"[{dll}] ({len(syms)} imports)")
    imp_lines.extend(f"  {s}" for s in syms)
(outdir/"pe_imports.txt").write_text("\n".join(imp_lines)+"\n", encoding="utf-8")
astrings=list(ascii_strings(data))
ustrings=list(utf16_strings(data))
(outdir/"strings_ascii.txt").write_text("\n".join(astrings)+"\n", encoding="utf-8")
(outdir/"strings_utf16le.txt").write_text("\n".join(ustrings)+"\n", encoding="utf-8")
print(f"Input: {src}")
print(f"File size: {len(data)} bytes")
print(f"PE offset: {peoff:#x}; machine: {machine:#06x}; sections: {nsects}; timestamp: {timestamp} (0x{timestamp:08x})")
print(f"Optional header: {'PE32+' if is64 else 'PE32'}; image base: {imagebase:#x}; entry RVA: {entry_rva:#x}; entry VA: {imagebase+entry_rva:#x}")
print(f"Section/file alignment: {section_align:#x}/{file_align:#x}; image/header size: {size_image:#x}/{size_headers:#x}; subsystem: {subsystem}; DLL characteristics: {dllchars:#06x}")
print("Data directories:")
for name,rva,size in dirs: print(f"  {name:14} RVA/offset={rva:#010x} size={size:#x}")
print("Sections:")
for name,vsize,va,rawsize,rawptr,chars in sects:
    raw=data[rawptr:min(len(data),rawptr+rawsize)]
    print(f"  {name:8} VA={va:#010x} VSize={vsize:#x} Raw={rawptr:#010x}+{rawsize:#x} entropy={entropy(raw):.3f} chars={chars:#010x}")
last=max([size_headers]+[rp+rs for _,_,_,rs,rp,_ in sects])
print(f"Overlay after last section raw byte {last:#x}: {max(0,len(data)-last)} bytes")
print(f"Imports: {sum(len(s) for _,s in imp)} symbols across {len(imp)} DLL descriptors; details in {outdir/'pe_imports.txt'}")
print(f"ASCII strings: {len(astrings)} saved to {outdir/'strings_ascii.txt'}")
print(f"UTF-16LE strings: {len(ustrings)} saved to {outdir/'strings_utf16le.txt'}")
terms=("flag","ctf","key","pass","decrypt","encrypt","aes","rsa","xor","secret","http","https","decode","base64","crypto","明文","密文","解密","密码","密钥")
matches=[]
for kind, seq in (("A",astrings),("U",ustrings)):
    for s in seq:
        if any(t.casefold() in s.casefold() for t in terms):
            matches.append((kind,s))
print("Keyword string matches:")
for kind,s in matches[:300]: print(f"  [{kind}] {s[:500]}")
if len(matches)>300: print(f"  ... {len(matches)-300} additional matches omitted from stdout; full string files preserved")