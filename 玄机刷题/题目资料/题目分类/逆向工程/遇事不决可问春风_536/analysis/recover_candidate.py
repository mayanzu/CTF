"""Recover the locally verifiable flag candidate from classes3.dex only."""
import struct
import sys
from pathlib import Path

data = Path(sys.argv[1]).read_bytes()
u16 = lambda o: struct.unpack_from("<H", data, o)[0]
u32 = lambda o: struct.unpack_from("<I", data, o)[0]
def uleb(pos):
    value = shift = 0
    while True:
        x = data[pos]; pos += 1
        value |= (x & 0x7f) << shift
        if not x & 0x80: return value, pos
        shift += 7

assert data[:4] == b"dex\n"
string_count, string_off = u32(56), u32(60)
type_count, type_off = u32(64), u32(68)
method_count, method_off = u32(88), u32(92)
class_count, class_off = u32(96), u32(100)
strings = []
for i in range(string_count):
    off = u32(string_off + 4*i); _, p = uleb(off); end = data.index(0, p)
    strings.append(data[p:end].decode("utf-8", "replace"))
types = [strings[u32(type_off + 4*i)] for i in range(type_count)]
methods = []
for i in range(method_count):
    class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", data, method_off + 8*i)
    methods.append((types[class_idx], strings[name_idx]))

owner = "Lcom/example/wakurev/MainActivity;"
code_by_name = {}
for ci in range(class_count):
    off = class_off + ci*32
    class_idx = u32(off); class_data_off = u32(off+24)
    if types[class_idx] != owner or not class_data_off: continue
    p = class_data_off
    counts=[]
    for _ in range(4): n,p=uleb(p); counts.append(n)
    for field_count in counts[:2]:
        for _ in range(field_count): _,p=uleb(p); _,p=uleb(p)
    for method_count_here in counts[2:]:
        idx=0
        for _ in range(method_count_here):
            diff,p=uleb(p); idx+=diff; _,p=uleb(p); code_off,p=uleb(p)
            code_by_name[methods[idx][1]]=code_off
    break
assert {"<clinit>", "decryptPassword", "buildFlag"} <= code_by_name.keys()

def code_units(name):
    off=code_by_name[name]
    size=u32(off+12); base=off+16
    return [u16(base+2*i) for i in range(size)]

clinit = code_units("<clinit>")
cipher = None
for i, unit in enumerate(clinit):
    if unit & 0xff == 0x1a:
        cipher = strings[clinit[i+1]]
        break
assert cipher is not None, "encrypted constant string not found in <clinit>"

decrypt = code_units("decryptPassword")
xors = []
for i, unit in enumerate(decrypt[:-1]):
    if unit & 0xff == 0xdf:  # DEX xor-int/lit8 (22b)
        literal = (decrypt[i+1] >> 8) & 0xff
        if literal & 0x80: literal -= 0x100
        xors.append(literal)
assert xors == [66], f"Expected one xor-int/lit8 immediate 66, saw {xors}"
assert any(unit & 0xff == 0x8e for unit in decrypt), "int-to-char cast not found"
key = xors[0]

check = code_units("checkPassword")
assert check[0] & 0xff == 0x70 and methods[check[1]][1] == "decryptPassword"
assert check[4] & 0xff == 0x6e and methods[check[5]][1] == "equals"
equals_arg_word = check[6]
equals_args = [equals_arg_word & 0xf, (equals_arg_word >> 4) & 0xf]
assert equals_args == [2, 0], equals_args

build = code_units("buildFlag")
fragments=[]
for i, unit in enumerate(build):
    if unit & 0xff == 0x1a:
        fragments.append(strings[build[i+1]])
prefix = next(s for s in fragments if s.startswith("flag{"))
suffix = next(s for s in fragments if s == "}")
password = "".join(chr(ord(ch) ^ key) for ch in cipher)
flag = prefix + password + suffix

print(f"DEX input: {Path(sys.argv[1]).name}")
print(f"Ciphertext from MainActivity.<clinit>: {cipher!r}")
print(f"decryptPassword operation: XOR immediate {key} (0x{key:02x}), then int-to-char")
print("checkPassword path: invoke decryptPassword(), then userInput.equals(decrypted)")
print(f"Password candidate ({len(password)} chars): {password}")
print(f"buildFlag literals: prefix={prefix!r}, suffix={suffix!r}")
print(f"Candidate flag: {flag}")
print("Character mapping (cipher hex -> recovered UTF-16 code unit):")
for i, ch in enumerate(cipher):
    print(f"  {i:02d}: U+{ord(ch):04X} -> U+{ord(ch)^key:04X} {password[i]!r}")
assert len(password) == len(cipher)
assert all(ord(out) == (ord(inp) ^ key) for inp, out in zip(cipher, password))
