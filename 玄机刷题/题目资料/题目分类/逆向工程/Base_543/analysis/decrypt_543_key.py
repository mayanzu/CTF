"""Invert the first-level 64-bit block check seen in the PE disassembly.

The program-specific transform is implemented from the straight-line arithmetic
in 0x140012816..0x14001288c; the executable is not executed.
"""
from __future__ import annotations
import pathlib

ROOT = pathlib.Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\Base_543")
LOG = ROOT / "records" / "543_key_decrypt_trace.txt"
MASK = 0xffffffff
DELTA = 0x9e3779b9
KEY = [0x12345678, 0x3456789a, 0x89abcdef, 0x12345678]
TARGET = (0xa92f3865, 0x9e60e953)


def mix(y: int, total: int, left: int, right: int) -> int:
    return (((((y << 4) & MASK) + left) & MASK) ^
            ((y + total) & MASK) ^
            (((y >> 5) + right) & MASK))


def encrypt(v0: int, v1: int, trace: list[str] | None = None) -> tuple[int, int]:
    total = 0
    for r in range(1, 33):
        total = (total + DELTA) & MASK
        old0, old1 = v0, v1
        v0 = (v0 + mix(v1, total, KEY[0], KEY[1])) & MASK
        v1 = (v1 + mix(v0, total, KEY[2], KEY[3])) & MASK
        if trace is not None and r in (1, 2, 31, 32):
            trace.append(f"ENC round {r:02}: sum=0x{total:08x} {old0:08x},{old1:08x} -> {v0:08x},{v1:08x}")
    return v0, v1


def decrypt(v0: int, v1: int, trace: list[str]) -> tuple[int, int]:
    total = (DELTA * 32) & MASK
    for r in range(32, 0, -1):
        old0, old1 = v0, v1
        v1 = (v1 - mix(v0, total, KEY[2], KEY[3])) & MASK
        v0 = (v0 - mix(v1, total, KEY[0], KEY[1])) & MASK
        if r in (32, 31, 2, 1):
            trace.append(f"DEC round {r:02}: sum=0x{total:08x} {old0:08x},{old1:08x} -> {v0:08x},{v1:08x}")
        total = (total - DELTA) & MASK
    return v0, v1

trace = [
    "First-level target output dwords from main: 0xa92f3865 and 0x9e60e953.",
    "Main passes data as two little-endian DWORDs; key words are 12345678,3456789a,89abcdef,12345678.",
    "Round: sum+=0x9e3779b9; v0+=mix(v1,sum,k0,k1); v1+=mix(v0,sum,k2,k3), modulo 2^32.",
    "mix(y,sum,a,b)=((y<<4)+a) XOR (y+sum) XOR ((y>>5)+b), modulo 2^32 on additions.",
]
plain_words = decrypt(*TARGET, trace)
plain = b"".join(w.to_bytes(4, "little") for w in plain_words)
verified = encrypt(*plain_words)
trace += [
    f"Decrypted words: 0x{plain_words[0]:08x}, 0x{plain_words[1]:08x}",
    "Little-endian input bytes: " + plain.hex(" "),
    "Input representation: " + repr(plain),
    "Forward check: " + ", ".join(f"0x{x:08x}" for x in verified),
    "Forward matches embedded target: " + str(verified == TARGET),
    "All eight bytes printable ASCII: " + str(all(0x20 <= c <= 0x7e for c in plain)),
]
LOG.write_text("\n".join(trace) + "\n", encoding="utf-8")
print("\n".join(trace))
print("trace_file=" + str(LOG))
if verified != TARGET:
    raise SystemExit("forward check failed")

