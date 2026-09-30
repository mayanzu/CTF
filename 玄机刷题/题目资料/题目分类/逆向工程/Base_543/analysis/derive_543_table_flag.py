"""Recover the custom Base32 table and invert the embedded encoded flag.

The transform and constants are read from objdump output; the PE is not executed.
"""
from __future__ import annotations
import pathlib, re, string

ROOT = pathlib.Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\Base_543")
DISASM = ROOT / "analysis" / "objdump_disassembly_intel_ascii.txt"
KEY = b"y0uokTea"
TARGET_TABLE_START = 0x220
TARGET_TABLE_END = 0x260
ENCODED_START = 0x2d8
ENCODED_END = 0x308
OUT = ROOT / "records" / "543_table_flag_derivation.txt"
text = DISASM.read_text(encoding="utf-8")

# Main writes both arrays as explicit immediate bytes to rbp-relative locals.
writes = {}
for line in text.splitlines():
    m = re.search(r"mov\s+BYTE PTR /[rbp\+0x([0-9a-f]+)/],0x([0-9a-f]+)", line, re.I)
    if m:
        writes[int(m.group(1),16)] = int(m.group(2),16)
try:
    encrypted_table = bytes(writes[i] for i in range(TARGET_TABLE_START,TARGET_TABLE_END))
    encoded = bytes(writes[i] for i in range(ENCODED_START,ENCODED_END))
except KeyError as e:
    raise SystemExit(f"missing immediate byte at rbp offset {e.args[0]:#x}")

# The disassembled key scheduling is RC4 KSA; its PRGA adds (not XORs) each
# keystream byte to the input modulo 256.
state = list(range(256))
j = 0
for i in range(256):
    j = (j + state[i] + KEY[i % len(KEY)]) & 0xff
    state[i], state[j] = state[j], state[i]
i = j = 0
stream = []
for _ in range(64):
    i = (i + 1) & 0xff
    j = (j + state[i]) & 0xff
    state[i], state[j] = state[j], state[i]
    stream.append(state[(state[i] + state[j]) & 0xff])
keystream = bytes(stream)
table = bytes((c - k) & 0xff for c,k in zip(encrypted_table,keystream))
forward = bytes((c + k) & 0xff for c,k in zip(table,keystream))
alphabet = table[1:33]
printable = all(0x20 <= c <= 0x7e for c in table)
unique = len(set(alphabet)) == 32
inverse = {c:i for i,c in enumerate(alphabet)}
missing = sorted(set(encoded)-set(alphabet))
bits = "".join(f"{inverse[c]:05b}" for c in encoded if c in inverse)
decoded = bytes(int(bits[k:k+8],2) for k in range(0,len(bits)-7,8)) if len(bits) >= 8 else b""
lines = [
    "Base_Table and flag derivation from PE immediates; no binary execution.",
    f"RC4/additive key: {KEY!r} (8 bytes from verified first-level inverse).",
    f"Encrypted 64-byte table hex: {encrypted_table.hex()}",
    f"64-byte keystream hex: {keystream.hex()}",
    "Operation in target: out[i]=(in[i]+keystream[i]) mod 256.",
    "Inverse: in[i]=(target[i]-keystream[i]) mod 256.",
    f"Recovered table bytes: {table!r}",
    f"Recovered table ASCII view: {table.decode('latin1')}",
    f"Recovered table hex: {table.hex()}",
    f"All table bytes printable ASCII: {printable}",
    f"Alphabet used by encoder (table[1:33]): {alphabet!r}",
    f"Alphabet length: {len(alphabet)}, unique entries: {len(set(alphabet))}",
    f"Expected 64-byte transformed table forward check: {forward.hex()}",
    f"Forward matches embedded table: {forward == encrypted_table}",
    f"Embedded Base32-like output bytes ({len(encoded)}): {encoded!r}",
    f"Embedded output as ASCII: {encoded.decode('ascii','replace')}",
    f"Target chars missing from alphabet: {bytes(missing)!r}",
    f"Decoded bytes from all {len(encoded)} output chars: {decoded!r}",
    f"Decoded bytes hex: {decoded.hex()}",
    f"Decoded length: {len(decoded)}",
    f"Decoded bytes without trailing zero: {decoded.rstrip(bytes([0]))!r}",
    f"Decoded text without trailing zero: {decoded.rstrip(bytes([0])).decode('ascii','replace')}",
]
OUT.write_text("\n".join(lines)+"\n",encoding="utf-8")
print("\n".join(lines))
print("report_file="+str(OUT))
if forward != encrypted_table:
    raise SystemExit("table forward check failed")

