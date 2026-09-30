from pathlib import Path
import hashlib
import struct

EXE = Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\PaluFlat_547\analysis\extracted\PaluFlat.exe")
HEAD_SIZE = 0x5000
IMAGE_BASE_EXPECTED = 0x400000
TABLE_VA = 0x405000
TABLE_COUNT = 0x2D + 1
TARGET_START_VA = 0x4020B4
TARGET_COUNT = 0x13

def u16(buf, off):
    return struct.unpack_from("<H", buf, off)[0]

def u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]

with EXE.open("rb") as fh:
    head = fh.read(HEAD_SIZE)

assert len(head) == HEAD_SIZE
assert head[:2] == b"MZ"
pe_off = u32(head, 0x3C)
assert head[pe_off:pe_off + 4] == b"PE\0\0"
coff = pe_off + 4
section_count = u16(head, coff + 2)
opt_size = u16(head, coff + 16)
opt = coff + 20
magic = u16(head, opt)
assert magic == 0x20B
image_base = struct.unpack_from("<Q", head, opt + 24)[0]
assert image_base == IMAGE_BASE_EXPECTED
sec_off = opt + opt_size
sections = []
for n in range(section_count):
    off = sec_off + 40 * n
    name = head[off:off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
    virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from("<IIII", head, off + 8)
    sections.append((name, virtual_address, virtual_size, raw_ptr, raw_size))

def rva_to_offset(rva, size=1):
    for name, va, vsize, raw_ptr, raw_size in sections:
        extent = max(vsize, raw_size)
        if va <= rva and rva + size <= va + extent:
            delta = rva - va
            if delta + size > raw_size:
                raise ValueError(f"{name}: requested bytes are virtual-only")
            off = raw_ptr + delta
            if off + size > len(head):
                raise ValueError(f"{name}: bytes exceed bounded header read")
            return off
    raise ValueError(f"RVA not mapped: {rva:#x}")

def va_bytes(va, size):
    return head[rva_to_offset(va - image_base, size):rva_to_offset(va - image_base, size) + size]

print("STATIC_INPUT_PATH =", EXE)
print("FILE_SIZE =", EXE.stat().st_size)
print("READ_BYTES =", len(head))
print("HEAD_SHA256 =", hashlib.sha256(head).hexdigest())
print("PE_OFFSET =", hex(pe_off), "SECTION_COUNT =", section_count, "IMAGE_BASE =", hex(image_base))
for name, va, vsize, raw_ptr, raw_size in sections:
    print(f"SECTION {name:8s} RVA={va:#06x} VSize={vsize:#06x} RawOff={raw_ptr:#06x} RawSize={raw_size:#06x}")

def cstr_rva(rva):
    off = rva_to_offset(rva, 1)
    end = head.find(b"\0", off)
    if end < 0:
        raise ValueError(f"unterminated C string at RVA {rva:#x}")
    return head[off:end].decode("ascii", "replace")

import_rva, import_size = struct.unpack_from("<II", head, opt + 120)
assert import_rva and import_size
import_off = rva_to_offset(import_rva, 20)
strlen_iat_va = None
for d in range(import_size // 20):
    desc = import_off + d * 20
    oft, stamp, chain, name_rva, first_thunk = struct.unpack_from("<IIIII", head, desc)
    if not any((oft, stamp, chain, name_rva, first_thunk)):
        break
    dll_name = cstr_rva(name_rva)
    lookup_rva = oft or first_thunk
    for j in range(256):
        entry_rva = lookup_rva + 8 * j
        entry_off = rva_to_offset(entry_rva, 8)
        value = struct.unpack_from("<Q", head, entry_off)[0]
        if value == 0:
            break
        if value & (1 << 63):
            continue
        import_name_rva = value & 0x7FFFFFFFFFFFFFFF
        symbol = cstr_rva(import_name_rva + 2)
        if symbol == "strlen":
            strlen_iat_va = image_base + first_thunk + 8 * j
            print(f"IMPORT {dll_name}!{symbol} IAT_VA={strlen_iat_va:#x}")
assert strlen_iat_va == 0x40937C
strlen_thunk = va_bytes(0x4036F0, 6)
rip_disp = struct.unpack("<i", strlen_thunk[2:6])[0]
rip_target = 0x4036F0 + 6 + rip_disp
assert rip_target == strlen_iat_va
print("STRLEN_THUNK_VA=0x4036f0 BYTES=", strlen_thunk.hex(), "RIP_TARGET=", hex(rip_target))
table_off = rva_to_offset(TABLE_VA - image_base, 4 * TABLE_COUNT)
table = []
for i in range(TABLE_COUNT):
    rel = struct.unpack_from("<i", head, table_off + 4 * i)[0]
    target_va = TABLE_VA + rel
    table.append(target_va)
print(f"JUMP_TABLE_VA={TABLE_VA:#x} RAW_OFFSET={table_off:#x} COUNT={TABLE_COUNT} STATE_RANGE=0..0x2d")
for i, addr in enumerate(table):
    print(f"STATE {i:02d} -> {addr:#010x}")

target = bytearray()
for i in range(TARGET_COUNT):
    va = TARGET_START_VA + 4 * i
    insn = va_bytes(va, 4)
    expected_disp = (0xA0 + i) & 0xFF
    assert insn[:3] == bytes((0xC6, 0x45, expected_disp)), (i, hex(va), insn.hex())
    target.append(insn[3])
target = bytes(target)
length_insn = va_bytes(0x402100, 10)
assert length_insn[:6] == bytes.fromhex("c7 85 94 00 00 00")
assert length_insn[6:10] == struct.pack("<I", TARGET_COUNT)
print("TARGET_INIT_VA_RANGE = 0x4020b4..0x4020ff")
print("TARGET_BYTES_HEX =", target.hex())
print("TARGET_BYTES_LEN =", len(target), "TARGET_REQUIRED_LENGTH_IMM =", TARGET_COUNT)
print("TARGET_NUL_OFFSETS =", [i for i, b in enumerate(target) if b == 0])
print("TARGET_LENGTH_STORE_BYTES =", length_insn.hex())

# The fixed seed is initialized in the state-machine prologue. Branch trace below
# follows immediate constants and the exact state assignments shown by the bytes.
seed = 0x3039
seed_insn = va_bytes(0x4015AE, 7)
assert seed_insn == bytes.fromhex("c7 45 d8 39 30 00 00")
def bit(n):
    return (seed >> n) & 1
print("SEED_INIT_BYTES =", seed_insn.hex(), "SEED =", hex(seed), "BITS0_2_6_7_8_9_10_11_13_14_15 =", "".join(str(bit(n)) for n in (0,2,6,7,8,9,10,11,13,14,15)))
path = [0, 10, 12, 2, 3, 4, 0]
print("ACTIVE_STATE_PATH_PER_BYTE =", " -> ".join(map(str, path)))
print("ACTIVE_PATH_BRANCH_FACTS = seed.bit0=1 selects state0 odd-seed arm; seed.bit2=0 selects state10; seed.bit13=1 and bit14=0 selects state12; seed.bits6,7,8=000 makes state2 select state3; seed.bits9,10,11=000 makes state3 select state4.")
print("ACTIVE_CODE_BYTES")
for state in (0, 10, 12, 2, 3, 4):
    addr = table[state]
    raw = va_bytes(addr, 16)
    print(f"  state={state:02d} va={addr:#010x} bytes16={raw.hex()}")

candidate = bytearray()
rows = []
for i, y in enumerate(target):
    key = b"palu" if i % 2 == 0 else b"flat"
    kb = key[i % 4]
    q = ((~y) + 0x55) & 0xFF
    # For a reachable result from the arithmetic-shift byte operation,
    # Q(x)=((x<<4)&255)|((signed8(x)>>4)&255), q must have low nibble <= 7.
    assert (q & 0x0F) <= 7, (i, hex(q))
    x = ((q & 0x0F) << 4) | (q >> 4)
    inp = x ^ kb
    candidate.append(inp)
    # Recompute the exact SAR/SHL/OR byte semantics, not a cipher helper.
    signed_x = x if x < 0x80 else x - 0x100
    q_forward = (((x << 4) & 0xFF) | ((signed_x >> 4) & 0xFF)) & 0xFF
    after_sub = (q_forward - 0x55) & 0xFF
    out = (~after_sub) & 0xFF
    assert out == y, (i, hex(out), hex(y))
    assert inp < 0x80
    rows.append((i, inp, kb, x, q_forward, after_sub, out))

candidate = bytes(candidate)
forward = bytearray()
for i, inp in enumerate(candidate):
    key = b"palu" if i % 2 == 0 else b"flat"
    kb = key[i % 4]
    x = inp ^ kb
    signed_x = x if x < 0x80 else x - 0x100
    q = (((x << 4) & 0xFF) | ((signed_x >> 4) & 0xFF)) & 0xFF
    after_sub = (q - 0x55) & 0xFF
    forward.append((~after_sub) & 0xFF)
forward = bytes(forward)
assert forward == target
print("CANDIDATE_REPR =", repr(candidate))
print("CANDIDATE_ASCII =", candidate.decode("ascii"))
print("CANDIDATE_HEX =", candidate.hex())
print("PER_BYTE_FORWARD_ROWS: idx,input,key,xor,q_after_SAR_SHL_OR,after_sub_55,not_output,target,match")
for i, inp, kb, x, q, after_sub, out in rows:
    print(f"ROW {i:02d} {inp:02x}({chr(inp)}) {kb:02x}({chr(kb)}) {x:02x} {q:02x} {after_sub:02x} {out:02x} {target[i]:02x} {out == target[i]}")
nul_at = forward.find(b"\0")
c_string_length = len(forward) if nul_at < 0 else nul_at
print("FORWARD_HEX =", forward.hex())
print("FORWARD_EXACT_TARGET_MATCH =", forward == target)
print("FIRST_OUTPUT_NUL_OFFSET =", nul_at)
print("C_STRLEN_OF_FORWARD =", c_string_length)
print("MAIN_REQUIRES_STRLEN =", TARGET_COUNT)
print("LENGTH_GATE_PASSES =", c_string_length == TARGET_COUNT)
print("STATIC_CONCLUSION = exact target bytes require output[16]=0; strlen(output) therefore cannot be 19, so the local main length gate makes success impossible even though this reverse-derived candidate matches every target byte before C-string truncation.")