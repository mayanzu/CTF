"""Retry PE static parsing from an ASCII-only temporary path.

The first objdump pass failed because the MSYS2 objdump process could not open the
Unicode path. The original failed outputs/log are preserved. This retries the
same read-only static tools after a byte-for-byte copy; no executable is run.
"""
from __future__ import annotations

import hashlib
import pathlib
import shutil
import subprocess

ROOT = pathlib.Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\Base_543")
SOURCE = ROOT / "analysis" / "unpacked" / "你知道Base么" / "你知道Base么.exe"
TEMP = pathlib.Path(r"C:\Users\mzj\Desktop\CTF\challenge543_static.exe")
OUT = ROOT / "analysis"
LOG = ROOT / "records" / "543_static_analysis_retry_transcript.txt"
LOG.parent.mkdir(parents=True, exist_ok=True)

source_hash = hashlib.sha256(SOURCE.read_bytes()).hexdigest().upper()
shutil.copyfile(SOURCE, TEMP)
temp_hash = hashlib.sha256(TEMP.read_bytes()).hexdigest().upper()
if source_hash != temp_hash:
    raise SystemExit("ASCII temp copy SHA-256 mismatch; static analysis stopped")

commands = [
    ("objdump_pe_header_ascii.txt", ["objdump", "-f", "-x", str(TEMP)]),
    ("objdump_sections_ascii.txt", ["objdump", "-h", str(TEMP)]),
    ("objdump_imports_ascii.txt", ["objdump", "-p", str(TEMP)]),
    ("strings_ascii_ascii.txt", ["strings", "-a", "-n", "3", str(TEMP)]),
    ("strings_utf16le_ascii.txt", ["strings", "-a", "-el", "-n", "3", str(TEMP)]),
    ("objdump_disassembly_intel_ascii.txt", ["objdump", "-d", "-M", "intel", "-w", str(TEMP)]),
]
log = [
    "Xuanji #543 static PE analysis retry transcript",
    "Reason: first objdump attempt against the Unicode path failed with 'No such file or directory'; original log/output preserved.",
    "Copy action: Python shutil.copyfile(SOURCE, TEMP), byte-for-byte hash checked.",
    "Source SHA256=" + source_hash,
    "ASCII-copy SHA256=" + temp_hash,
    "All following commands are static parsers/readers. The executable was never launched.",
    "",
]
for filename, argv in commands:
    proc = subprocess.run(argv, capture_output=True, check=False)
    out = proc.stdout.decode("utf-8", "replace").replace("\r\n", "\n")
    err = proc.stderr.decode("utf-8", "replace").replace("\r\n", "\n")
    (OUT / filename).write_text(out, encoding="utf-8")
    log += [
        "COMMAND> " + " ".join(argv),
        f"EXIT_CODE> {proc.returncode}",
        f"STDOUT_FILE> {OUT / filename}",
        f"STDOUT_BYTES> {len(proc.stdout)}",
        "STDERR_BEGIN",
        err.rstrip("\n"),
        "STDERR_END",
        "",
    ]
LOG.write_text("\n".join(log) + "\n", encoding="utf-8")
print("source_sha256=" + source_hash)
print("temp_sha256=" + temp_hash)
print("transcript=" + str(LOG))
for filename, _ in commands:
    out = OUT / filename
    print(f"{filename} bytes={out.stat().st_size}")
