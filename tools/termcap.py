#!/usr/bin/env python3
"""termcap.py — 在真实 shell 中执行命令，把「命令 + 真实输出」记录成终端实录文件。

用途：为讲义生成可复现的终端截图素材。所有输出都来自真实执行，禁止手工编造。

用法示例（Windows PowerShell 命令）：
    python tools/termcap.py --out figures/raw/web-curl.txt --shell ps ^
        --cmd "python --version" ^
        --cmd "curl.exe -i http://127.0.0.1:8765/gate?role=guest"

WSL bash 命令：
    python tools/termcap.py --out figures/raw/pwn-build.txt --shell wsl ^
        --cmd "cd /mnt/c/Users/mzj/Desktop/CTF/CTF-training-problem-first-full && gcc -O0 -fno-stack-protector -no-pie -o labs/pwn/overflow labs/pwn/overflow.c"

需要先起服务再执行命令时：
    python tools/termcap.py --out figures/raw/web-notes.txt --shell ps ^
        --server "python labs/web/app.py" --wait 2 ^
        --cmd "curl.exe -s http://127.0.0.1:8765/notes?title=public"

只想截「服务启动画面」时，直接把启动命令当普通命令跑，并用 --timeout 结束：
    python tools/termcap.py --out figures/raw/web-server.txt --shell ps ^
        --cmd "python labs/web/app.py" --timeout 4

说明：
- 每条 --cmd 生成一行提示符 + 该命令的真实输出。
- --timeout 只对单条命令生效；超时会终止该命令并保留已产生的输出。
- 输出统一 UTF-8 解码（错误字符替换为 U+FFFD）。
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path


def run_one(cmd: str, shell: str, cwd: Path, timeout: float, env: dict) -> tuple[str, str, bool]:
    """执行一条命令，返回 (stdout+stderr, 提示符, 是否超时)。"""
    if shell == "wsl":
        argv = ["wsl", "-d", "Ubuntu-24.04", "--", "bash", "-lc", cmd]
        prompt = "mzj@Ubuntu-24.04:~$ "
    else:
        wrapped = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + cmd
        argv = ["powershell", "-NoProfile", "-Command", wrapped]
        prompt = f"PS {cwd}> "
    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd),
            env=env,
            capture_output=True,
            timeout=timeout,
        )
        raw = (proc.stdout or b"") + (proc.stderr or b"")
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        raw = (exc.stdout or b"") + (exc.stderr or b"")
        timed_out = True
    text = raw.decode("utf-8", errors="replace")
    # 去掉 ANSI 控制序列，避免截图里出现乱码
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)
    text = text.replace("\r\n", "\n").replace("\r", "")
    text = "\n".join(line.rstrip() for line in text.split("\n")).strip("\n")
    return text, prompt, timed_out


def main() -> int:
    ap = argparse.ArgumentParser(description="记录真实终端实录（命令 + 真实输出）")
    ap.add_argument("--out", required=True, help="输出的实录文本文件（建议放 figures/raw/）")
    ap.add_argument("--shell", choices=["ps", "wsl"], default="ps", help="ps=Windows PowerShell，wsl=Ubuntu-24.04")
    ap.add_argument("--cmd", action="append", default=[], help="要执行的命令，可重复")
    ap.add_argument("--cwd", default=None, help="工作目录，默认当前目录")
    ap.add_argument("--server", default=None, help="先在后台启动的服务命令（其输出不进实录）")
    ap.add_argument("--wait", type=float, default=2.0, help="服务启动等待秒数")
    ap.add_argument("--timeout", type=float, default=60.0, help="单条命令超时秒数")
    ap.add_argument("--note", action="append", default=[], help="实录开头的注释行（# 开头，不渲染）")
    args = ap.parse_args()

    if not args.cmd:
        ap.error("至少要有一条 --cmd")

    cwd = Path(args.cwd or os.getcwd()).resolve()
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")

    server_proc = None
    if args.server:
        if args.shell == "wsl":
            sargv = ["wsl", "-d", "Ubuntu-24.04", "--", "bash", "-lc", args.server]
        else:
            sargv = ["powershell", "-NoProfile", "-Command", args.server]
        server_proc = subprocess.Popen(sargv, cwd=str(cwd), env=env,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        import time
        time.sleep(args.wait)

    lines: list[str] = []
    for note in args.note:
        lines.append("# " + note)
    for cmd in args.cmd:
        out, prompt, timed_out = run_one(cmd, args.shell, cwd, args.timeout, env)
        lines.append(f"{prompt}{cmd}")
        if out:
            lines.append(out)
        if timed_out:
            lines.append("[命令持续运行，此处截断]")
        lines.append("")

    if server_proc is not None:
        server_proc.terminate()
        try:
            server_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server_proc.kill()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    print(f"[ok] 实录已写入 {out_path}（{len(args.cmd)} 条命令）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
