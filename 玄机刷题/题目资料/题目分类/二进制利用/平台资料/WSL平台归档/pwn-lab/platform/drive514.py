"""临时驱动（用完即删）：连 514 实例，解 PoW，然后按命令行参数依次发送菜单输入并打印回显。

用法：python3 drive514.py "1" "16" "payload" "3" "0" "6"
"""
import hashlib
import itertools
import re
import socket
import string
import sys
import time

HOST, PORT = "env.xj.edisec.net", 31888


def drain(s, wait=0.8, bufsize=8192):
    """收干净：在 wait 秒内把能读到的都读出来。"""
    s.settimeout(0.25)
    buf = b""
    end = time.monotonic() + wait
    while time.monotonic() < end:
        try:
            d = s.recv(bufsize)
        except socket.timeout:
            continue
        if not d:
            break
        buf += d
    return buf


def solve_pow(md5hex, masked):
    pos = [i for i, ch in enumerate(masked) if ch == "_"]
    fixed = list(masked)
    for combo in itertools.product(string.ascii_uppercase, repeat=len(pos)):
        for i, ch in zip(pos, combo):
            fixed[i] = ch
        cand = "".join(fixed)
        if hashlib.md5(cand.encode()).hexdigest() == md5hex:
            return "".join(combo)
    raise SystemExit("pow failed")


s = socket.create_connection((HOST, PORT), timeout=6)
banner = drain(s, 1.5)
masked = re.search(rb"Token:\s*([A-Za-z_]+)", banner).group(1).decode()
md5hex = re.search(rb"MD5:\s*([0-9a-f]{32})", banner).group(1).decode()
missing = solve_pow(md5hex, masked)
print("[pow] %s -> %s" % (masked, missing))
s.sendall(missing.encode() + b"\n")
print("[menu]", repr(drain(s, 1.5)))

for arg in sys.argv[1:]:
    m = re.fullmatch(r"H([0-9a-fA-F]{2})x(\d+)", arg)
    if m:
        line = (m.group(1) * int(m.group(2))).encode()
    else:
        line = arg.encode().decode("unicode_escape").encode("latin-1")
    s.sendall(line + b"\n")
    print("[send %s]" % (line[:40] + (b"..." if len(line) > 40 else b"")), repr(drain(s, 1.0)))
s.close()