from pathlib import Path
import hashlib, struct
p = Path(__file__).resolve().parent / 'ezbase_unpacked.exe'
b = p.read_bytes()
rd16 = lambda o: struct.unpack_from('<H', b, o)[0]
rd32 = lambda o: struct.unpack_from('<I', b, o)[0]
pe = rd32(0x3c)
nsec = rd16(pe + 6)
opt = pe + 24
image_base = rd32(opt + 28)
sec_table = opt + rd16(pe + 20)
sections=[]
for i in range(nsec):
    o=sec_table+i*40
    name=b[o:o+8].split(b'\0',1)[0]
    vsize, va, rawsize, rawptr=struct.unpack_from('<IIII',b,o+8)
    sections.append((name,vsize,va,rawsize,rawptr))
def rva_file_offset(rva):
    for name,vsize,va,rawsize,rawptr in sections:
        if va <= rva < va + max(vsize,rawsize):
            delta=rva-va
            if delta >= rawsize:
                raise ValueError(f'RVA {rva:#x} is virtual-only')
            return rawptr+delta
    raise ValueError(f'RVA {rva:#x} has no section')
# The disassembly's alphabet address is VA 0x406060.
alphabet_off=rva_file_offset(0x406060-image_base)
alphabet=b[alphabet_off:alphabet_off+64]
assert b[alphabet_off+64:alphabet_off+72] == b'You Find', b[alphabet_off+64:alphabet_off+72]
assert len(alphabet)==64, (len(alphabet),alphabet)
assert len(set(alphabet))==64, 'custom alphabet is not bijective'
# Rebuild the 56-byte comparison constant from main's immediate stores at [esp+3e..75].
main_va=0x4015d7
main_off=rva_file_offset(main_va-image_base)
expected=bytearray(56)
seen=[]
for disp in range(0x3e,0x76,4):
    needle=b'\xc7\x44\x24'+bytes([disp])
    pos=b.find(needle, main_off, main_off+0x100)
    assert pos >= 0, f'missing immediate store for stack displacement {disp:#x}'
    chunk=b[pos+4:pos+8]
    expected[disp-0x3e:disp-0x3e+4]=chunk
    seen.append((disp,chunk))
expected=bytes(expected)
assert len(expected)==56
# main swaps encoded bytes at indices 0x0c and 0x12 before memcmp: undo it first.
encoded=bytearray(expected)
encoded[0x0c],encoded[0x12]=encoded[0x12],encoded[0x0c]
inv={c:i for i,c in enumerate(alphabet)}
raw=bytearray()
for i in range(0,len(encoded),4):
    a,c,d,e=(inv[x] for x in encoded[i:i+4])
    raw.extend(((a<<2)|(c>>4),((c&15)<<4)|(d>>2),((d&3)<<6)|e))
plain=bytes(x^0x10 for x in raw)
def custom_b64(data):
    out=bytearray()
    for i in range(0,len(data),3):
        x,y,z=data[i:i+3]
        out.extend((alphabet[x>>2],alphabet[((x&3)<<4)|(y>>4)],alphabet[((y&15)<<2)|(z>>6)],alphabet[z&63]))
    return bytes(out)
reencoded=bytearray(custom_b64(bytes(x^0x10 for x in plain)))
reencoded[0x0c],reencoded[0x12]=reencoded[0x12],reencoded[0x0c]
assert bytes(reencoded)==expected, 'forward re-encoding does not match target'
print('unpacked_sha256='+hashlib.sha256(b).hexdigest().upper())
print('section_map='+repr(sections))
print(f'alphabet_file_offset={alphabet_off:#x} alphabet_len={len(alphabet)} alphabet={alphabet.decode("ascii")}')
print('target_store_bytes='+repr(seen))
print(f'target_encoded={expected.decode("ascii")} length={len(expected)}')
print(f'after_undo_swap={bytes(encoded).decode("ascii")}')
print(f'decoded_pre_xor_hex={raw.hex()} length={len(raw)}')
print(f'plaintext_hex={plain.hex()} length={len(plain)}')
print(f'plaintext_repr={plain!r}')
print(f'plaintext_ascii={plain.decode("ascii")}')
print(f'forward_reencode_match={bytes(reencoded)==expected}')
