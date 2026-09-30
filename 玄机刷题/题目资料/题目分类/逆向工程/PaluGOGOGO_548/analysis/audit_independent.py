"""Independent static audit for PaluGOGOGO #548; reads ZIP/PE bytes only."""
from pathlib import Path
import hashlib
import struct
import zipfile

HERE = Path(__file__).resolve().parent
ZIP_PATH = HERE.parent / "originals" / "palugogogo_flag.zip"
EXTRACTED = HERE / "palugogogo_flag.exe"
EXPECTED_ZIP_SHA256 = "420820830348B3791655E6912DE1DBF84C066F876F9AAC0859F19E91A6A92FF1"
MASK64 = (1 << 64) - 1
MASK63 = (1 << 63) - 1
INT31MAX = (1 << 31) - 1
RNG_LEN = 607
RNG_TAP = 273
SEED_MOD = INT31MAX

zip_bytes = ZIP_PATH.read_bytes()
zip_hash = hashlib.sha256(zip_bytes).hexdigest().upper()
assert zip_hash == EXPECTED_ZIP_SHA256, (zip_hash, EXPECTED_ZIP_SHA256)
with zipfile.ZipFile(ZIP_PATH, "r") as archive:
    entries = archive.infolist()
    assert len(entries) == 1, [entry.filename for entry in entries]
    entry = entries[0]
    assert entry.filename == "palugogogo_flag.exe"
    assert "/" not in entry.filename and "\\" not in entry.filename and not entry.filename.startswith(".")
    pe_bytes = archive.read(entry)
entry_hash = hashlib.sha256(pe_bytes).hexdigest().upper()
disk_bytes = EXTRACTED.read_bytes()
disk_hash = hashlib.sha256(disk_bytes).hexdigest().upper()
assert pe_bytes == disk_bytes

def u16(data, off):
    return struct.unpack_from("<H", data, off)[0]

def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]

def u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]

assert pe_bytes[:2] == b"MZ"
peoff = u32(pe_bytes, 0x3C)
assert pe_bytes[peoff:peoff + 4] == b"PE\0\0"
machine = u16(pe_bytes, peoff + 4)
section_count = u16(pe_bytes, peoff + 6)
optional_size = u16(pe_bytes, peoff + 20)
optional = peoff + 24
assert u16(pe_bytes, optional) == 0x20B
imagebase = u64(pe_bytes, optional + 24)
section_table = optional + optional_size
sections = []
for index in range(section_count):
    off = section_table + 40 * index
    name = pe_bytes[off:off + 8].split(b"\0", 1)[0].decode("ascii")
    virtual_size, rva, raw_size, raw_ptr = struct.unpack_from("<IIII", pe_bytes, off + 8)
    sections.append((name, rva, virtual_size, raw_size, raw_ptr))

def va_to_offset(va, length=1):
    rva = va - imagebase
    for name, sec_rva, virtual_size, raw_size, raw_ptr in sections:
        if sec_rva <= rva and rva + length <= sec_rva + raw_size:
            return raw_ptr + rva - sec_rva
    raise ValueError(f"VA 0x{va:x} length {length} is not file-backed")

# Addresses come from saved static disassembly: rngSource.Seed table and checkFlag target.
cooked_va = 0x551DE0
cooked_off = va_to_offset(cooked_va, RNG_LEN * 8)
cooked_blob = pe_bytes[cooked_off:cooked_off + RNG_LEN * 8]
cooked = list(struct.unpack("<607q", cooked_blob))
target_va = 0x4BF204
target_off = va_to_offset(target_va, 0x54)
target_blob = pe_bytes[target_off:target_off + 0x54]
target_text = target_blob.decode("ascii")
tokens = target_text.split(",")
assert len(target_blob) == 84 and len(tokens) == 17
encoded = [int(token, 16) for token in tokens]
assert all(token.startswith("0x") for token in tokens)

def seedrand(x):
    return (48271 * x) % SEED_MOD

def initialize_go_source(seed, cooked_words):
    seed %= SEED_MOD
    if seed < 0:
        seed += SEED_MOD
    if seed == 0:
        seed = 89482311
    x = seed
    vector = [0] * RNG_LEN
    for i in range(-20, RNG_LEN):
        x = seedrand(x)
        if i >= 0:
            word = (x << 40) & MASK64
            x = seedrand(x)
            word ^= (x << 20) & MASK64
            x = seedrand(x)
            word ^= x
            word ^= cooked_words[i] & MASK64
            vector[i] = word & MASK64
    return {"vector": vector, "tap": 0, "feed": RNG_LEN - RNG_TAP}

def next_int63(state):
    state["tap"] -= 1
    if state["tap"] < 0:
        state["tap"] += RNG_LEN
    state["feed"] -= 1
    if state["feed"] < 0:
        state["feed"] += RNG_LEN
    value = (state["vector"][state["feed"]] + state["vector"][state["tap"]]) & MASK64
    state["vector"][state["feed"]] = value
    return value & MASK63

def next_int31(state):
    return next_int63(state) >> 32

def go_int31n(state, n):
    assert n > 0
    if n & (n - 1) == 0:
        raw = next_int31(state)
        return raw & (n - 1), [raw], None
    cutoff = INT31MAX - 1 - (INT31MAX % n)
    draws = []
    while True:
        raw = next_int31(state)
        draws.append(raw)
        if raw <= cutoff:
            return raw % n, draws, cutoff

seed = 996
state = initialize_go_source(seed, cooked)
draw_log = []
values = []
for i in range(10):
    value, draws, cutoff = go_int31n(state, 100)
    values.append(value)
    draw_log.append((f"Intn(100)[{i}]", value, draws, cutoff))
index, draws, cutoff = go_int31n(state, 2)
draw_log.append(("Intn(2)", index, draws, cutoff))
key = values[index]
codepoints = [value - key - (i % 5) for i, value in enumerate(encoded)]
assert all(0 <= cp <= 0x7F for cp in codepoints)
candidate = "".join(chr(cp) for cp in codepoints)
forward_text = ",".join(f"0x{ord(ch) + key + (i % 5):x}" for i, ch in enumerate(candidate))
assert forward_text == target_text
assert forward_text.encode("ascii") == target_blob
assert candidate.startswith("flag{") and candidate.endswith("}")
prefix_keys = [encoded[i] - ord(ch) - (i % 5) for i, ch in enumerate("flag{")]
assert prefix_keys == [key] * 5

print("AUDIT_SCOPE=static ZIP/PE bytes only; no PE load/execute; no platform access")
print(f"ZIP_SHA256={zip_hash}")
print(f"ZIP_ENTRIES={len(entries)}; entry={entry.filename}; uncompressed={entry.file_size}; compressed={entry.compress_size}")
print(f"INNER_PE_SHA256={entry_hash}; extracted_SHA256={disk_hash}; byte_identical={pe_bytes == disk_bytes}")
print(f"PE_MACHINE=0x{machine:04x}; PE32+=True; imagebase=0x{imagebase:x}; sections={section_count}")
print("PE_SECTIONS=" + "; ".join(f"{name}:RVA=0x{rva:x},raw=0x{raw_ptr:x},size=0x{raw_size:x}" for name, rva, _vs, raw_size, raw_ptr in sections))
print(f"RNG_COOKED_VA=0x{cooked_va:x}; file_offset=0x{cooked_off:x}; entries={len(cooked)}; SHA256={hashlib.sha256(cooked_blob).hexdigest().upper()}")
print("RNG_COOKED_FIRST4=" + ",".join(f"{word & MASK64:016x}" for word in cooked[:4]))
print(f"TARGET_VA=0x{target_va:x}; file_offset=0x{target_off:x}; byte_length={len(target_blob)}; token_count={len(tokens)}")
print(f"TARGET={target_text}")
print(f"GO_SEED={seed}; seedrand_multiplier=48271; modulus={SEED_MOD}; warmup=20; tap=0; feed={RNG_LEN-RNG_TAP}")
for label, value, draws, cutoff in draw_log:
    print(f"{label}: raw31={draws}; cutoff={cutoff}; result={value}")
print(f"INTN100_VALUES={values}")
print(f"NEXT_INTN2_INDEX={index}; GETVALUE_KEY={key}")
print("DECODED_CODEPOINTS=" + " ".join(f"U+{cp:04X}" for cp in codepoints))
print(f"CANDIDATE={candidate}")
print(f"FORWARD={forward_text}")
print(f"FORWARD_MATCHES_ALL_84_BYTES={forward_text.encode('ascii') == target_blob}")
print(f"PREFIX_CROSSCHECK_KEYS={prefix_keys}")
print("PLATFORM_ACCESS=none (not checked by this offline audit)")

