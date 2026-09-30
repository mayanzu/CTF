"""Minimal read-only DEX parser/disassembler for the app's small classes3.dex."""
import struct
import sys
from pathlib import Path

p = Path(sys.argv[1])
b = p.read_bytes()
u16 = lambda o: struct.unpack_from("<H", b, o)[0]
u32 = lambda o: struct.unpack_from("<I", b, o)[0]
def s16(v): return v - 0x10000 if v & 0x8000 else v
def s32(v): return v - 0x100000000 if v & 0x80000000 else v
def uleb(pos):
    value = shift = 0
    while True:
        x = b[pos]; pos += 1
        value |= (x & 0x7f) << shift
        if not x & 0x80: return value, pos
        shift += 7

assert b[:4] == b"dex\n", f"Not DEX: {b[:8]!r}"
header = {
    "version": b[4:7].decode("ascii", "replace"),
    "file_size": u32(32), "header_size": u32(36),
    "string_ids_size": u32(56), "string_ids_off": u32(60),
    "type_ids_size": u32(64), "type_ids_off": u32(68),
    "proto_ids_size": u32(72), "proto_ids_off": u32(76),
    "field_ids_size": u32(80), "field_ids_off": u32(84),
    "method_ids_size": u32(88), "method_ids_off": u32(92),
    "class_defs_size": u32(96), "class_defs_off": u32(100),
}
print("DEX", p.name, "version", header["version"], "file_size", header["file_size"])
for k, v in header.items():
    if k.endswith("_size"): print(f"  {k}: {v}")

strings = []
for i in range(header["string_ids_size"]):
    off = u32(header["string_ids_off"] + 4*i)
    _, q = uleb(off)
    end = b.index(0, q)
    strings.append(b[q:end].decode("utf-8", "replace"))
types = [strings[u32(header["type_ids_off"] + 4*i)] for i in range(header["type_ids_size"])]
def read_type_list(off):
    if off == 0: return []
    size = u32(off)
    return [types[u16(off + 4 + 2*i)] for i in range(size)]
protos = []
for i in range(header["proto_ids_size"]):
    shorty_idx, ret_idx, params_off = struct.unpack_from("<III", b, header["proto_ids_off"] + 12*i)
    protos.append((types[ret_idx], read_type_list(params_off)))
fields = []
for i in range(header["field_ids_size"]):
    ci, ti, ni = struct.unpack_from("<HHI", b, header["field_ids_off"] + 8*i)
    fields.append((types[ci], types[ti], strings[ni]))
methods = []
for i in range(header["method_ids_size"]):
    ci, pi, ni = struct.unpack_from("<HHI", b, header["method_ids_off"] + 8*i)
    methods.append((types[ci], strings[ni], protos[pi]))
def method_sig(m):
    owner, name, (ret, args) = m
    return f"{owner}->{name}({''.join(args)}){ret}"

def encoded_value(pos):
    head=b[pos]; pos+=1; arg=head>>5; typ=head&0x1f
    if typ == 0x1e: return None,pos
    if typ == 0x1f: return bool(arg),pos
    if typ == 0x1c:
        count,pos=uleb(pos); vals=[]
        for _ in range(count): v,pos=encoded_value(pos); vals.append(v)
        return vals,pos
    n=arg+1
    raw=int.from_bytes(b[pos:pos+n], "little", signed=False); pos+=n
    if typ == 0x00:
        bits=n*8; raw=raw-(1<<bits) if raw>>(bits-1) else raw
    elif typ == 0x02:
        bits=n*8; raw=raw-(1<<bits) if raw>>(bits-1) else raw
    elif typ == 0x03: pass
    elif typ == 0x04:
        bits=n*8; raw=raw-(1<<bits) if raw>>(bits-1) else raw
    elif typ == 0x06:
        bits=n*8; raw=raw-(1<<bits) if raw>>(bits-1) else raw
    elif typ in (0x17,0x18): raw = strings[raw] if typ == 0x17 else types[raw]
    elif typ in (0x19,0x1a,0x1b): raw = raw
    else: raw = f"value_type_0x{typ:02x}:{raw}"
    return raw,pos

widths = {i:1 for i in range(256)}
for op in [0x02,0x05,0x08,0x13,0x15,0x16,0x19,0x1a,0x1c,0x1f,0x20,0x22,0x23,0x29,
           0x2d,0x2e,0x2f,0x30,0x31,*range(0x32,0x3e),*range(0x44,0x6e),*range(0xd0,0xe3),0xfc,0xfd]: widths[op]=2
for op in [0x03,0x06,0x09,0x14,0x17,0x18,0x1b,0x24,0x25,0x26,0x2a,0x2b,0x2c,
           *range(0x6e,0x73),*range(0x74,0x79),0xfb]: widths[op]=3
widths[0xfa]=4
names = {
  0x00:"nop",0x01:"move",0x02:"move/from16",0x03:"move/16",0x04:"move-wide",0x07:"move-object",
  0x0a:"move-result",0x0b:"move-result-wide",0x0c:"move-result-object",0x0d:"move-exception",
  0x0e:"return-void",0x0f:"return",0x10:"return-wide",0x11:"return-object",
  0x12:"const/4",0x13:"const/16",0x14:"const",0x15:"const/high16",0x16:"const-wide/16",0x17:"const-wide/32",
  0x18:"const-wide",0x19:"const-wide/high16",0x1a:"const-string",0x1b:"const-string/jumbo",0x1c:"const-class",
  0x1d:"monitor-enter",0x1e:"monitor-exit",0x1f:"check-cast",0x20:"instance-of",0x21:"array-length",
  0x22:"new-instance",0x23:"new-array",0x24:"filled-new-array",0x25:"filled-new-array/range",
  0x26:"fill-array-data",0x27:"throw",0x28:"goto",0x29:"goto/16",0x2a:"goto/32",0x2b:"packed-switch",0x2c:"sparse-switch",
  0x32:"if-eq",0x33:"if-ne",0x34:"if-lt",0x35:"if-ge",0x36:"if-gt",0x37:"if-le",0x38:"if-eqz",0x39:"if-nez",
  0x3a:"if-ltz",0x3b:"if-gez",0x3c:"if-gtz",0x3d:"if-lez",0x44:"aget",0x45:"aget-wide",0x46:"aget-object",
  0x47:"aget-boolean",0x48:"aget-byte",0x49:"aget-char",0x4a:"aget-short",0x4b:"aput",0x4c:"aput-wide",
  0x4d:"aput-object",0x4e:"aput-boolean",0x4f:"aput-byte",0x50:"aput-char",0x51:"aput-short",
  0x52:"iget",0x53:"iget-wide",0x54:"iget-object",
  0x59:"iput",0x5a:"iput-wide",0x5b:"iput-object",0x60:"sget",0x61:"sget-wide",0x62:"sget-object",
  0x67:"sput",0x68:"sput-wide",0x69:"sput-object",0x6e:"invoke-virtual",0x6f:"invoke-super",0x70:"invoke-direct",
  0x71:"invoke-static",0x72:"invoke-interface",0x74:"invoke-virtual/range",0x75:"invoke-super/range",
  0x76:"invoke-direct/range",0x77:"invoke-static/range",0x78:"invoke-interface/range",0x7b:"neg-int",0x7c:"not-int",
  0x7d:"neg-long",0x7e:"not-long",0x7f:"neg-float",0x80:"neg-double",0x81:"int-to-long",0x82:"int-to-float",
  0x83:"int-to-double",0x84:"long-to-int",0x85:"long-to-float",0x86:"long-to-double",0x87:"float-to-int",
  0x88:"float-to-long",0x89:"float-to-double",0x8a:"double-to-int",0x8b:"double-to-long",0x8c:"double-to-float",
  0x8d:"int-to-byte",0x8e:"int-to-char",0x8f:"int-to-short",0x90:"add-int",0x91:"sub-int",0x92:"mul-int",0x93:"div-int",0x94:"rem-int",
  0x95:"and-int",0x96:"or-int",0x97:"xor-int",0xa0:"shl-int",0xa1:"shr-int",0xa2:"ushr-int",
  0xd0:"add-int/lit16",0xd1:"rsub-int",0xd2:"mul-int/lit16",0xd3:"div-int/lit16",0xd4:"rem-int/lit16",
  0xd5:"and-int/lit16",0xd6:"or-int/lit16",0xd7:"xor-int/lit16",0xd8:"add-int/lit8",0xd9:"rsub-int/lit8",
  0xda:"mul-int/lit8",0xdb:"div-int/lit8",0xdc:"rem-int/lit8",0xdd:"and-int/lit8",0xde:"or-int/lit8",
  0xdf:"xor-int/lit8",0xe0:"shl-int/lit8",0xe1:"shr-int/lit8",0xe2:"ushr-int/lit8"
}
def s8(v): return v - 256 if v & 0x80 else v

def decode_insns(code_off):
    regs, ins, outs, tries = struct.unpack_from("<HHHH", b, code_off)
    insns_size = u32(code_off + 12); base = code_off + 16
    units = [u16(base + 2*i) for i in range(insns_size)]
    print(f"  code: registers={regs} ins={ins} outs={outs} tries={tries} units={insns_size}")
    pc = 0
    while pc < len(units):
        w = units[pc]; op = w & 0xff
        if op == 0 and w >> 8 in (1,2,3):
            ident = w >> 8
            if ident == 1:
                n=units[pc+1]; width=4+2*n; desc=f"packed-switch size={n}"
            elif ident == 2:
                n=units[pc+1]; width=2+4*n; desc=f"sparse-switch size={n}"
            else:
                ew=units[pc+1]; n=units[pc+2] | (units[pc+3]<<16); width=4+(n*ew+1)//2
                data=b[base+2*(pc+4):base+2*(pc+4)+n*ew]; desc=f"array-data width={ew} count={n} bytes={data.hex()}"
            print(f"    {pc:04x}: <{desc}>"); pc += width; continue
        width=widths[op]; x=units[pc:pc+width]; aa=(w>>8)&0xff; line=names.get(op,f"op_{op:02x}")
        if op == 0x12:
            a=(w>>8)&0xf; lit=(w>>12)&0xf; lit=lit-16 if lit&8 else lit; line+=f" v{a}, #{lit}"
        elif op in (0x13,0x16): line+=f" v{aa}, #{s16(x[1])}"
        elif op in (0x14,0x17): line+=f" v{aa}, #{s32(x[1] | (x[2]<<16))}"
        elif op == 0x15: line+=f" v{aa}, #{s16(x[1])<<16}"
        elif op in (0x1a,0x1b):
            idx=x[1] if op==0x1a else x[1] | (x[2]<<16); line+=f" v{aa}, string@{idx}={strings[idx]!r}"
        elif op in (0x1c,0x1f,0x20): line+=f" v{aa}, type@{x[1]}={types[x[1]]}"
        elif op == 0x21: line+=f" v{(w>>8)&0xf}, v{(w>>12)&0xf}"
        elif op in (0x22,): line+=f" v{aa}, type@{x[1]}={types[x[1]]}"
        elif op == 0x23: line+=f" v{(w>>8)&0xf}, v{(w>>12)&0xf}, type@{x[1]}={types[x[1]]}"
        elif op == 0x28: line+=f" +{s8(aa)} -> {pc+s8(aa):04x}"
        elif op == 0x29: line+=f" +{s16(x[1])} -> {pc+s16(x[1]):04x}"
        elif op == 0x2a: line+=f" +{s32(x[1] | (x[2]<<16))} -> {pc+s32(x[1] | (x[2]<<16)):04x}"
        elif 0x32 <= op <= 0x37:
            off=s16(x[1]); line+=f" v{(w>>8)&0xf}, v{(w>>12)&0xf}, +{off} -> {pc+off:04x}"
        elif 0x38 <= op <= 0x3d:
            off=s16(x[1]); line+=f" v{aa}, +{off} -> {pc+off:04x}"
        elif 0x44 <= op <= 0x51:
            if op in (0x4b,0x4c,0x4d): line+=f" v{x[1]&0xff}, v{x[1]>>8}, v{aa}"
            else: line+=f" v{aa}, v{x[1]&0xff}, v{x[1]>>8}"
        elif 0x60 <= op <= 0x6d:
            idx=x[1]; line+=f" v{aa}, field@{idx}={fields[idx][0]}->{fields[idx][2]}:{fields[idx][1]}"
        elif 0x6e <= op <= 0x72:
            count=(w>>12)&0xf; g=(w>>8)&0xf; idx=x[1]; rs=x[2]
            rs=[rs&0xf,(rs>>4)&0xf,(rs>>8)&0xf,(rs>>12)&0xf,g][:count]
            line+=f" {{{','.join('v'+str(r) for r in rs)}}}, method@{idx}={method_sig(methods[idx])}"
        elif 0x74 <= op <= 0x78:
            idx=x[1]; start=x[2]; line+=f" {{v{start}..v{start+aa-1}}}, method@{idx}={method_sig(methods[idx])}"
        elif 0xd0 <= op <= 0xd3: line+=f" v{(w>>8)&0xf}, #{s16(x[1])}"
        elif 0xd8 <= op <= 0xe2: line+=f" v{aa}, v{x[1]&0xff}, #{s8(x[1]>>8)}"
        elif op in (0x01,0x04,0x07): line+=f" v{(w>>8)&0xf}, v{(w>>12)&0xf}"
        elif 0x7b <= op <= 0x8f: line+=f" v{(w>>8)&0xf}, v{(w>>12)&0xf}"
        elif op in (0x02,0x05,0x08): line+=f" v{aa}, v{x[1]}"
        elif op in (0x03,0x06,0x09): line+=f" v{aa}, v{x[1]}, v{x[2]}"
        elif op in (0x0a,0x0b,0x0c,0x0d,0x0f,0x10,0x11,0x27): line+=f" v{aa}"
        print(f"    {pc:04x}: {line} [{ ' '.join(f'{q:04x}' for q in x) }]")
        pc += max(width,1)

for ci in range(header["class_defs_size"]):
    off=header["class_defs_off"]+ci*32
    ci_idx, access, super_idx, interfaces_off, source_idx, annotations_off, class_data_off, static_values_off = struct.unpack_from("<IIIIIIII",b,off)
    owner=types[ci_idx]
    print(f"\nCLASS {owner} access=0x{access:x} source={strings[source_idx] if source_idx != 0xffffffff else '-'}")
    if super_idx != 0xffffffff: print(f"  extends {types[super_idx]}")
    if not class_data_off: continue
    pos=class_data_off; counts=[]
    for _ in range(4): n,pos=uleb(pos); counts.append(n)
    print(f"  class_data static_fields={counts[0]} instance_fields={counts[1]} direct_methods={counts[2]} virtual_methods={counts[3]}")
    static_rows=[]
    for kind,n in zip(("static","instance"),counts[:2]):
        idx=0
        for _ in range(n):
            diff,pos=uleb(pos); idx+=diff; flags,pos=uleb(pos); f=fields[idx]
            print(f"  {kind} field {f[2]}: {f[1]} access=0x{flags:x}")
            if kind == "static": static_rows.append(f)
    if static_values_off:
        n_values,value_pos=uleb(static_values_off)
        vals=[]
        for _ in range(n_values): value,value_pos=encoded_value(value_pos); vals.append(value)
        print(f"  encoded static values: {list(zip([f[2] for f in static_rows], vals))}")
    for kind,n in zip(("direct","virtual"),counts[2:]):
        idx=0
        for _ in range(n):
            diff,pos=uleb(pos); idx+=diff; flags,pos=uleb(pos); code_off,pos=uleb(pos); m=methods[idx]
            print(f"\n  METHOD {method_sig(m)} access=0x{flags:x} code_off=0x{code_off:x}")
            if code_off: decode_insns(code_off)
            else: print("  no code")
