"""Collect static PE metadata, disassembly, and string listings for challenge 543.

All tools used here parse bytes statically; the challenge executable is never run.
"""
from __future__ import annotations

import pathlib
import shutil
import subprocess

ROOT = pathlib.Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\Base_543")
EXE = ROOT / "analysis" / "unpacked" / "你知道Base么" / "你知道Base么.exe"
OUT = ROOT / "analysis"
LOG = ROOT / "records" / "543_static_analysis_transcript.txt"
LOG.parent.mkdir(parents=True, exist_ok=True)

commands = [
    ("objdump_pe_header.txt", ["objdump", "-f", "-x", str(EXE)]),
    ("objdump_sections.txt", ["objdump", "-h", str(EXE)]),
    ("objdump_imports.txt", ["objdump", "-p", str(EXE)]),
    ("strings_ascii.txt", ["strings", "-a", "-n", "3", str(EXE)]),
    ("strings_utf16le.txt", ["strings", "-a", "-el", "-n", "3", str(EXE)]),
    ("objdump_disassembly_intel.txt", ["objdump", "-d", "-M", "intel", "-w", str(EXE)]),
]
log = [
    "Xuanji #543 static PE analysis transcript",
    "Scope: static parsing only. The challenge executable was never launched.",
    "Input: " + str(EXE),
    "",
]
for filename, argv in commands:
    if shutil.which(argv[0]) is None:
        log += [f"COMMAND> {' '.join(argv)}", "ERROR> executable not found on PATH", ""]
        continue
    p = subprocess.run(argv, capture_output=True, check=False)
    out = p.stdout.decode("utf-8", "replace").replace("\r\n", "\n")
    err = p.stderr.decode("utf-8", "replace").replace("\r\n", "\n")
    (OUT / filename).write_text(out, encoding="utf-8")
    log += [
        "COMMAND> " + " ".join(argv),
        f"EXIT_CODE> {p.returncode}",
        f"STDOUT_FILE> {OUT / filename}",
        f"STDOUT_BYTES> {len(p.stdout)}",
        "STDERR_BEGIN",
        err.rstrip("\n"),
        "STDERR_END",
        "",
    ]
LOG.write_text("\n".join(log) + "\n", encoding="utf-8")
print("transcript=" + str(LOG))
for filename, _ in commands:
    p = OUT / filename
    if p.exists():
        print(f"{filename} bytes={p.stat().st_size}")

