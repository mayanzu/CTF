"""Safe, read-only RAR member inventory for Xuanji challenge 543.

This script invokes only `tar -tf` and `tar -tvf` to list the archive. It does
not extract or execute any archive member.
"""
from __future__ import annotations

import hashlib
import pathlib
import subprocess

ROOT = pathlib.Path(r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\Base_543")
ARCHIVE = ROOT.parents[2] / "原始下载附件" / "你知道Base么-20250521104202-am92t17.rar"
TRANSCRIPT = ROOT / "records" / "543_inventory_transcript.txt"
TRANSCRIPT.parent.mkdir(parents=True, exist_ok=True)


def run_and_decode(argv: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(argv, capture_output=True, check=False)
    # bsdtar emits the legacy GBK filenames found in this RAR as GBK bytes.
    return (
        proc.returncode,
        proc.stdout.decode("gbk", "replace").replace("\r\n", "\n"),
        proc.stderr.decode("gbk", "replace").replace("\r\n", "\n"),
    )


sha256 = hashlib.sha256(ARCHIVE.read_bytes()).hexdigest().upper()
transcript_lines = [
    "Xuanji #543 Base.rar safe inventory",
    "Purpose: inspect the archive directory before any extraction.",
    "No challenge executable was run.",
    "",
    "COMMAND> Get-FileHash -Algorithm SHA256 -LiteralPath " + str(ARCHIVE),
    "OUTPUT> SHA256=" + sha256,
    "",
]
for verbose in (True, False):
    args = ["tar", "-tvf" if verbose else "-tf", str(ARCHIVE)]
    cmd = "tar.exe " + ("-tvf" if verbose else "-tf") + " " + str(ARCHIVE)
    rc, stdout, stderr = run_and_decode(args)
    transcript_lines += [
        "COMMAND> " + cmd,
        f"EXIT_CODE> {rc}",
        "OUTPUT_BEGIN",
        stdout.rstrip("\n"),
        "OUTPUT_END",
    ]
    if stderr:
        transcript_lines += ["STDERR_BEGIN", stderr.rstrip("\n"), "STDERR_END"]
    transcript_lines.append("")
    if rc != 0:
        TRANSCRIPT.write_text("\n".join(transcript_lines) + "\n", encoding="utf-8")
        raise SystemExit(f"tar listing failed (exit {rc}); see {TRANSCRIPT}")

rc, names_text, _ = run_and_decode(["tar", "-tf", str(ARCHIVE)])
names = [n.strip() for n in names_text.splitlines() if n.strip()]
unsafe = []
for name in names:
    normalized = name.replace("//", "/")
    parts = normalized.split("/")
    if normalized.startswith("/") or ":" in normalized or ".." in parts:
        unsafe.append(name)

transcript_lines += [
    "PATH_VALIDATION>",
    f"members={len(names)}",
    "members_safe=" + str(not unsafe),
    "unsafe_members=" + repr(unsafe),
    "Decision: do not extract unless members_safe=True and the member list is reviewed.",
]
TRANSCRIPT.write_text("\n".join(transcript_lines) + "\n", encoding="utf-8")
print(f"archive_sha256={sha256}")
print(f"member_count={len(names)}")
for name in names:
    print("member=" + name)
print("unsafe_members=" + repr(unsafe))
print("transcript=" + str(TRANSCRIPT))
if unsafe:
    raise SystemExit("unsafe member path found; extraction is blocked")

