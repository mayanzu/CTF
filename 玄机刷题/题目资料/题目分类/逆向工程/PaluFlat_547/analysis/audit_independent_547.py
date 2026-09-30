from pathlib import Path
import hashlib
import re
import struct
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parent.parent
ANALYSIS = ROOT / "analysis"
ZIP_PATH = ROOT / "originals" / "PaluFlat_flag.zip"
COM_PATH = ANALYSIS / "extracted" / "PaluFlat_flag.com"
EXE_PATH = ANALYSIS / "extracted" / "PaluFlat.exe"
HEAD_PATH = ANALYSIS / "PaluFlat_head_0x5000.bin"
CHUNK = 4 * 1024 * 1024
IMAGE_BASE_EXPECTED = 0x400000

def say(s=""):
    print(s, flush=True)

def stream_hash(path):
    h = hashlib.sha256()
    total = 0
    with path.open("rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            h.update(b)
            total += len(b)
    return total, h.hexdigest().upper()

def stream_from_pipe(pipe, n):
    out = bytearray()
    while len(out) < n:
        part = pipe.read(n - len(out))
        if not part:
            break
        out.extend(part)
    return bytes(out)

say("AUDIT_SCOPE = static-only; no challenge .com or .exe executed")
say("MAX_BUFFERED_CHUNK = 4194304 bytes; no 1 GiB whole-file reads")
say("COMMAND> Python zipfile: list/test outer ZIP and stream-compare its sole member to the saved .com")
zip_size, zip_hash = stream_hash(ZIP_PATH)
say(f"OUTER_ZIP_SIZE = {zip_size}")
say(f"OUTER_ZIP_SHA256 = {zip_hash}")
with zipfile.ZipFile(ZIP_PATH) as zf:
    infos = zf.infolist()
    say("OUTER_ZIP_MEMBERS = " + repr([(x.filename, x.file_size, x.compress_size, f"{x.CRC:08X}") for x in infos]))
    assert [x.filename for x in infos] == ["PaluFlat_flag.com"]
    assert infos[0].file_size == COM_PATH.stat().st_size
    assert zf.testzip() is None
    with zf.open(infos[0], "r") as src, COM_PATH.open("rb") as saved:
        zipped_hash = hashlib.sha256()
        saved_hash = hashlib.sha256()
        total = 0
        while True:
            a = src.read(CHUNK)
            b = saved.read(CHUNK)
            assert len(a) == len(b), (len(a), len(b))
            if not a:
                break
            assert a == b, f"ZIP member differs from saved .com at offset {total}"
            zipped_hash.update(a)
            saved_hash.update(b)
            total += len(a)
        assert total == infos[0].file_size
        assert zipped_hash.digest() == saved_hash.digest()
say(f"OUTER_ZIP_CRC_TEST = PASS")
say(f"ZIP_MEMBER_EQUALS_SAVED_COM = PASS; size={total}; sha256={saved_hash.hexdigest().upper()}")

say("COMMAND> tar -tvf <PaluFlat_flag.com> (list only; no extraction)")
listing_cmd = ["tar", "-tvf", str(COM_PATH)]
listing = subprocess.run(listing_cmd, capture_output=True, text=True, errors="replace")
say("ARGV_ASCII_ESCAPED = " + repr(["tar", "-tvf", str(COM_PATH).encode("unicode_escape").decode("ascii")]))
say("EXIT_CODE = " + str(listing.returncode))
say("STDOUT_BEGIN")
say(listing.stdout.rstrip())
say("STDOUT_END")
say("STDERR = " + repr(listing.stderr))
assert listing.returncode == 0
listing_lines = [line for line in listing.stdout.splitlines() if line.strip()]
assert len(listing_lines) == 1, listing_lines
assert listing_lines[0].split()[-1] == "PaluFlat.exe"
assert re.search(r"\b1073741824\b", listing_lines[0]), listing_lines[0]
say("INNER_7Z_MEMBERS = ['PaluFlat.exe']; declared_size=1073741824; path_is_flat=PASS")

say("COMMAND> tar -xOf <PaluFlat_flag.com> PaluFlat.exe | bounded stream compare against saved PE")
extract_cmd = ["tar", "-xOf", str(COM_PATH), "PaluFlat.exe"]
say("ARGV_ASCII_ESCAPED = " + repr(["tar", "-xOf", str(COM_PATH).encode("unicode_escape").decode("ascii"), "PaluFlat.exe"]))
proc = subprocess.Popen(extract_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
assert proc.stdout is not None
saved_exe_hash = hashlib.sha256()
archive_exe_hash = hashlib.sha256()
saved_total = 0
archive_total = 0
with EXE_PATH.open("rb") as saved:
    while True:
        a = stream_from_pipe(proc.stdout, CHUNK)
        b = saved.read(CHUNK)
        if not a and not b:
            break
        assert len(a) == len(b), (archive_total, len(a), len(b))
        assert a == b, f"inner 7z stream differs from saved PE at offset {archive_total}"
        archive_exe_hash.update(a)
        saved_exe_hash.update(b)
        archive_total += len(a)
        saved_total += len(b)
proc.stdout.close()
stderr = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
return_code = proc.wait()
say("EXIT_CODE = " + str(return_code))
say("STDERR = " + repr(stderr))
assert return_code == 0
assert archive_total == 1 << 30
assert saved_total == archive_total
assert archive_exe_hash.digest() == saved_exe_hash.digest()
say(f"INNER_7Z_STREAM_EQUALS_SAVED_PE = PASS; size={saved_total}; sha256={saved_exe_hash.hexdigest().upper()}")

say("COMMAND> bounded PE parse: read exactly first 0x5000 bytes from saved PE")
with EXE_PATH.open("rb") as f:
    head = f.read(0x5000)
assert len(head) == 0x5000
assert HEAD_PATH.read_bytes() == head
pe_off = struct.unpack_from("<I", head, 0x3C)[0]
assert head[:2] == b"MZ" and head[pe_off:pe_off+4] == b"PE\0\0"
coff = pe_off + 4
machine, nsects, _, _, _, opt_size, characteristics = struct.unpack_from("<HHIIIHH", head, coff)
opt = coff + 20
magic = struct.unpack_from("<H", head, opt)[0]
image_base = struct.unpack_from("<Q", head, opt + 24)[0]
entry_rva = struct.unpack_from("<I", head, opt + 16)[0]
size_image = struct.unpack_from("<I", head, opt + 56)[0]
size_headers = struct.unpack_from("<I", head, opt + 60)[0]
assert machine == 0x8664 and magic == 0x20B and image_base == IMAGE_BASE_EXPECTED
assert nsects == 9 and size_headers <= len(head)
say(f"PE_OFFSET = {pe_off:#x}; MACHINE = {machine:#06x}; OPTIONAL_MAGIC = {magic:#06x}; IMAGE_BASE = {image_base:#x}")
say(f"ENTRY_POINT_VA = {image_base + entry_rva:#x}; SIZE_OF_IMAGE = {size_image:#x}; SIZE_OF_HEADERS = {size_headers:#x}; SECTION_COUNT = {nsects}")
sections = []
sec_off = opt + opt_size
for i in range(nsects):
    off = sec_off + i * 40
    name = head[off:off+8].split(b"\0", 1)[0].decode("ascii", "replace")
    vsize, rva, raw_size, raw_ptr = struct.unpack_from("<IIII", head, off+8)
    sections.append((name, rva, vsize, raw_ptr, raw_size))
raw_intervals = []
for name, rva, vsize, raw_ptr, raw_size in sections:
    raw_end = raw_ptr + raw_size
    say(f"SECTION {name:8s} RVA={rva:#06x} VSize={vsize:#06x} RawOff={raw_ptr:#06x} RawSize={raw_size:#06x} RawEnd={raw_end:#06x}")
    if raw_size:
        assert raw_ptr >= size_headers
        assert raw_end <= len(head), (name, raw_end, len(head))
        raw_intervals.append((raw_ptr, raw_end, name))
for left, right in zip(sorted(raw_intervals), sorted(raw_intervals)[1:]):
    assert left[1] <= right[0], (left, right)
assert max(b for _, b, _ in raw_intervals) == 0x4800
say("PE_RAW_SECTIONS = non-overlapping, fully inside bounded 0x5000 read; last raw end=0x4800")

def rva_to_off(rva, size=1):
    for name, srva, vsize, raw_ptr, raw_size in sections:
        extent = max(vsize, raw_size)
        if srva <= rva and rva + size <= srva + extent:
            delta = rva - srva
            if delta + size > raw_size:
                raise ValueError(f"{name}: virtual-only data requested")
            off = raw_ptr + delta
            assert off + size <= len(head)
            return off
    raise ValueError(f"unmapped RVA {rva:#x}")

def va_bytes(va, size):
    return head[rva_to_off(va - image_base, size):rva_to_off(va - image_base, size) + size]

say("COMMAND> independent PE table/target/state parse from the bounded source prefix")
table_va = 0x405000
table_off = rva_to_off(table_va-image_base, 46*4)
states = []
for i in range(46):
    rel = struct.unpack_from("<i", head, table_off + 4*i)[0]
    states.append(table_va + rel)
say("JUMP_TABLE_COUNT = 46; STATE_RANGE = 0..45")
say("JUMP_TABLE = " + ", ".join(f"{i}:{va:#x}" for i, va in enumerate(states)))
assert states[0] == 0x4015E2 and states[2] == 0x401785 and states[3] == 0x401855
assert states[4] == 0x40191A and states[10] == 0x401A2A and states[12] == 0x401ADE

seed_ins = va_bytes(0x4015AE, 7)
assert seed_ins == bytes.fromhex("c7 45 d8 39 30 00 00")
seed = struct.unpack_from("<I", seed_ins, 3)[0]
bits = {n: (seed >> n) & 1 for n in range(16)}
say(f"SEED = {seed:#x}; BITS0_TO_15 = " + "".join(str(bits[n]) for n in range(16)))
assert [bits[n] for n in (0,2,6,7,8,9,10,11,13,14)] == [1,0,0,0,0,0,0,0,1,0]
say("ACTIVE_PATH_PER_BYTE = 0 -> 10 -> 12 -> 2 -> 3 -> 4 -> 0")
say("PATH_BRANCH_EVIDENCE = state0 tests bit0 at 0x4015fe; bit0=1 enters 0x401654; state0 then tests bit2 at 0x401654; bit2=0 sets state10 at 0x401689; state10 tests bit13/14 at 0x401a52/0x401a6e, yielding state12; state12 XORs input/key then sets state2; state2 tests bits6,7,8, all zero -> state3; state3 subtracts 0x55, tests bits9,10,11, all zero -> state4; state4 NOTs/writes and returns state0.")
state2 = va_bytes(states[2], 16)
state3 = va_bytes(states[3], 12)
state4 = va_bytes(states[4], 22)
assert state2[:15] == bytes.fromhex("0f be 45 eb c1 e0 04 89 c2 0f b6 45 eb c0 f8")
assert state3[:7] == bytes.fromhex("0f b6 45 eb 83 e8 55")
assert state4[:3] == bytes.fromhex("f6 55 eb")
say("STATE2_BYTES = " + state2.hex())
say("STATE3_BYTES = " + state3.hex())
say("STATE4_BYTES = " + state4.hex())
say("STATE2_SEMANTICS = temp is sign-extended for SHL EAX,4; a separate MOVZX then SAR AL,4 feeds OR EAX,EDX; for candidate XOR bytes all <0x80 this is exact nibble swap. For high-bit bytes SAR fills low nibble with F, so do not generalize nibble-swap simplification to arbitrary bytes.")
say("STATE3_SEMANTICS = byte(temp - 0x55) modulo 256; STATE4_SEMANTICS = bitwise NOT on byte")

target = bytearray()
for i in range(19):
    ins = va_bytes(0x4020B4 + i*4, 4)
    assert ins[:3] == bytes((0xC6, 0x45, 0xA0+i)), (i, ins.hex())
    target.append(ins[3])
target = bytes(target)
length_ins = va_bytes(0x402100, 10)
assert length_ins == bytes.fromhex("c7 85 94 00 00 00 13 00 00 00")
say("TARGET_BYTES = " + target.hex())
say("TARGET_LEN_IMMEDIATE = 19; TARGET_NUL_INDICES = " + repr([i for i,b in enumerate(target) if b == 0]))
palu_ins = va_bytes(0x401560, 7)
flat_ins = va_bytes(0x40156B, 8)
assert palu_ins[3:7] == b"palu" and flat_ins[3:7] == b"flat"
palu = palu_ins[3:7]
flat = flat_ins[3:7]
key = bytes((palu if i % 2 == 0 else flat)[i % 4] for i in range(19))
say(f"KEY_STRINGS = {palu!r}, {flat!r}; KEY_STREAM = {key.hex()}")

candidate = bytearray()
rows = []
for i, y in enumerate(target):
    after_not = (~y) & 0xFF
    q = (after_not + 0x55) & 0xFF
    assert (q & 0x0F) != 0x0F, (i, q)
    x = ((q & 0x0F) << 4) | (q >> 4)
    k = key[i]
    inp = x ^ k
    candidate.append(inp)
    assert x < 0x80 and inp < 0x80
    # Execute the exact AL arithmetic-right-shift semantics.
    signed_x = x if x < 0x80 else x - 0x100
    sar = (signed_x >> 4) & 0xFF
    q_forward = (((x << 4) & 0xFF) | sar) & 0xFF
    after_sub = (q_forward - 0x55) & 0xFF
    out = (~after_sub) & 0xFF
    assert out == y
    rows.append((i, y, inp, k, x, q_forward, after_sub, out))
candidate = bytes(candidate)
assert candidate == b"flag{bdm23Ne6ljz5O}"
forward = bytearray()
for i, inp in enumerate(candidate):
    x = inp ^ key[i]
    signed_x = x if x < 0x80 else x - 0x100
    q = (((x << 4) & 0xFF) | ((signed_x >> 4) & 0xFF)) & 0xFF
    forward.append((~((q - 0x55) & 0xFF)) & 0xFF)
forward = bytes(forward)
assert forward == target
say("CANDIDATE = " + candidate.decode("ascii"))
say("CANDIDATE_HEX = " + candidate.hex())
say("ROW_FORMAT = index target input key xor/intermediate q after_sub output equality")
for i, y, inp, k, x, q, after_sub, out in rows:
    say(f"ROW {i:02d} target={y:02x} input={inp:02x} key={k:02x} xor={x:02x} q={q:02x} sub={after_sub:02x} output={out:02x} match={out==y}")
say("FORWARD_BYTES = " + forward.hex())
say("FORWARD_EXACT_19_BYTE_MATCH = " + str(forward == target))

# Resolve the call target as an imported strlen thunk using the PE import table.
import_rva, import_size = struct.unpack_from("<II", head, opt + 120)
assert import_rva and import_size
def cstr_rva(rva):
    off = rva_to_off(rva)
    end = head.find(b"\0", off)
    assert end >= 0
    return head[off:end].decode("ascii", "replace")
desc_off = rva_to_off(import_rva, 20)
strlen_iat = None
for i in range(import_size // 20):
    doff = desc_off + 20*i
    oft, stamp, chain, name_rva, first_thunk = struct.unpack_from("<IIIII", head, doff)
    if not any((oft,stamp,chain,name_rva,first_thunk)):
        break
    dll = cstr_rva(name_rva)
    lookup = oft or first_thunk
    for j in range(256):
        val = struct.unpack_from("<Q", head, rva_to_off(lookup + 8*j, 8))[0]
        if val == 0:
            break
        if val >> 63:
            continue
        symbol = cstr_rva(val + 2)
        if dll.lower() == "msvcrt.dll" and symbol == "strlen":
            strlen_iat = image_base + first_thunk + 8*j
            break
assert strlen_iat == 0x40937C
thunk = va_bytes(0x4036F0, 6)
assert thunk[:2] == b"\xff\x25"
disp = struct.unpack_from("<i", thunk, 2)[0]
assert 0x4036F0 + 6 + disp == strlen_iat
main_call = va_bytes(0x40216A, 5)
assert main_call[0] == 0xE8 and 0x40216A + 5 + struct.unpack_from("<i", main_call,1)[0] == 0x4036F0
target_nul = target.index(0)
forward_strlen = forward.index(0) if 0 in forward else len(forward)
assert target_nul == 16 and forward_strlen == 16
say(f"IMPORT_RESOLUTION = msvcrt.dll!strlen -> IAT {strlen_iat:#x}; call at 0x40216a reaches thunk 0x4036f0")
say(f"MAIN_LENGTH_GATE = output strlen must equal 19 before 19-byte compare; exact target has NUL at offset 16, forward output strlen={forward_strlen}; LENGTH_GATE_PASSES=False")
say("STATIC_CONCLUSION = candidate is exactly determined by invertible target relation on all 19 bytes and forward-recomputes fully; the supplied PE's own success path is internally unreachable due strlen/embedded-NUL contradiction.")
say("PLATFORM_STATUS = not checked by this audit; candidate remains pending platform verification")
