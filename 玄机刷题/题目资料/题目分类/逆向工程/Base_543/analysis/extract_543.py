"""Extract only the reviewed safe member names from the #543 RAR archive.

No member is executed. Destination must be empty before extraction.
"""
from __future__ import annotations

import hashlib
import pathlib
import subprocess

ROOT = pathlib.Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\Base_543")
ARCHIVE = ROOT.parents[2] / "原始下载附件" / "你知道Base么-20250521104202-am92t17.rar"
DEST = ROOT / "analysis" / "unpacked"
LOG = ROOT / "records" / "543_extraction_transcript.txt"
MEMBERS = ["你知道Base么/你知道Base么.exe", "你知道Base么"]

if DEST.exists() and any(DEST.iterdir()):
    raise SystemExit(f"Refusing to extract into non-empty destination: {DEST}")
DEST.mkdir(parents=True, exist_ok=True)
args = ["tar", "-xf", str(ARCHIVE), "-C", str(DEST), "--", *MEMBERS]
proc = subprocess.run(args, capture_output=True, check=False)
try:
    stdout = proc.stdout.decode("gbk", "replace").replace("\r\n", "\n")
    stderr = proc.stderr.decode("gbk", "replace").replace("\r\n", "\n")
except Exception:
    stdout, stderr = repr(proc.stdout), repr(proc.stderr)

lines = [
    "Xuanji #543 reviewed-member extraction",
    "Safety: extracted only the two names from inventory_543.py; no executable was launched.",
    "Destination was empty before extraction: True",
    "COMMAND> tar.exe -xf " + str(ARCHIVE) + " -C " + str(DEST) + " -- " + " ".join(MEMBERS),
    f"EXIT_CODE> {proc.returncode}",
    "STDOUT_BEGIN",
    stdout.rstrip("\n"),
    "STDOUT_END",
    "STDERR_BEGIN",
    stderr.rstrip("\n"),
    "STDERR_END",
]
if proc.returncode:
    LOG.write_text("\n".join(lines) + "\n", encoding="utf-8")
    raise SystemExit(f"tar extraction failed (exit {proc.returncode}); see {LOG}")

exe = DEST / "你知道Base么" / "你知道Base么.exe"
if not exe.is_file():
    LOG.write_text("\n".join(lines + ["ERROR> expected executable absent"]) + "\n", encoding="utf-8")
    raise SystemExit(f"expected member was not extracted; see {LOG}")
digest = hashlib.sha256(exe.read_bytes()).hexdigest().upper()
entries = sorted((p.relative_to(DEST).as_posix(), p.stat().st_size if p.is_file() else 0) for p in DEST.rglob("*"))
lines += [
    "EXTRACTED_MEMBER_SHA256> " + digest,
    "EXTRACTED_TREE>",
    *[f"{name} | size={size}" for name, size in entries],
]
LOG.write_text("\n".join(lines) + "\n", encoding="utf-8")
print("exit_code=" + str(proc.returncode))
print("exe_size=" + str(exe.stat().st_size))
print("exe_sha256=" + digest)
print("extracted_entries=" + str(entries))
print("transcript=" + str(LOG))

