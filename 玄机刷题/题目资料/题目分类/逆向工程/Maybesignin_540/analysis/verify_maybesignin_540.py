#!/usr/bin/env python3
"""Replay correct and obsolete-key candidates against the original challenge EXE."""
from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
EXE = ROOT / "附件解包" / "ezsignin.exe"
SOLVER = HERE / "solve_maybesignin_540.py"

spec = importlib.util.spec_from_file_location("sm4solve", SOLVER)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load SM4 solver")
sm4 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sm4)

binary = EXE.read_bytes()
print(f"original EXE name: {EXE.name}")
print(f"original EXE SHA256: {hashlib.sha256(binary).hexdigest().upper()}")

# Reproduce the first wrong guess: one continuous byte sequence 01..10 (hex),
# instead of expanding each immediate as little-endian bytes.
wrong_key = bytes(range(1, 17))
target = bytes.fromhex("1c84be5145ce1af31fa3f75e3a38d0be")
wrong_candidate = sm4.crypt_block(target, wrong_key, decrypt=True)
correct_candidate = b"flag{wlascJDAFS}"

for label, candidate in (
    ("old continuous-byte-sequence key guess", wrong_candidate),
    ("correct little-endian immediate decoding", correct_candidate),
):
    payload = candidate + b"\n"
    completed = subprocess.run(
        [str(EXE)], input=payload, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=5, check=False
    )
    print(f"case: {label}")
    print(f"candidate bytes hex: {candidate.hex()}")
    print(f"stdin bytes repr: {payload!r}")
    print(f"exit code: {completed.returncode}")
    print(f"stdout repr: {completed.stdout!r}")
    print(f"stderr repr: {completed.stderr!r}")
