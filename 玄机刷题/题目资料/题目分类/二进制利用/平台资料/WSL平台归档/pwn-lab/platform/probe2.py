#!/usr/bin/env python3
"""514 安全标定探针：PoW -> 边界/布局 -> 打印带注解的 dump。非破坏性。"""
import hashlib, itertools, re, socket, string, sys, time, struct

HOST = sys.argv[1] if len(sys.argv) > 1 else "env.xj.edisec.net"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 30410


def drain(s, wait=0.7, bufsize=32768):
    s.settimeout(0.2)
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
        if hashlib.md5("".join(fixed).encode()).hexdigest() == md5hex:
            return "".join(combo)
    raise SystemExit("pow failed")


class C:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=8)
        b = drain(self.s, 1.5)
        masked = re.search(rb"Token:\s*([A-Za-z_]+)", b).group(1).decode()
        md5hex = re.search(rb"MD5:\s*([0-9a-f]{32})", b).group(1).decode()
        ans = solve_pow(md5hex, masked)
        print("[pow] %s -> %s" % (masked, ans), flush=True)
        self.send(ans, 1.2)

    def send(self, line, wait=0.6):
        line = str(line)
        try:
            self.s.sendall(line.encode() + b"\n")
        except OSError as e:
            print("[SEND-FAIL %r] %s" % (e, line), flush=True)
            return b""
        return drain(self.s, wait)

    def create(self, idx, title, reserve, length, hexdata):
        self.send(1); self.send(idx); self.send(title); self.send(reserve); self.send(length)
        return self.send(hexdata)

    def edit(self, idx, length, hexdata):
        self.send(2); self.send(idx); self.send(length)
        return self.send(hexdata)

    def show(self, idx, wait=0.9):
        self.send(3)
        return self.send(idx, wait)

    def pack(self, idx):
        self.send(4)
        return self.send(idx)

    def delete(self, idx):
        self.send(5)
        return self.send(idx)


def parse(r):
    m = re.search(rb"len=(\d+) cap=(\d+)\n([0-9a-f]*)\n", r)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), bytes.fromhex(m.group(3).decode())


def annotate(tag, r):
    d = parse(r)
    if not d:
        print("  %-14s RAW %r" % (tag, r[:160]), flush=True)
        return None
    ln, cap, blob = d
    print("  %-14s len=%-4d cap=%-4d bytes=%d" % (tag, ln, cap, len(blob)), flush=True)
    for off in range(0, len(blob), 8):
        chunk = blob[off:off + 8]
        q = struct.unpack("<Q", chunk.ljust(8, b"\x00"))[0]
        print("      +0x%03x  %-23s  q=0x%016x" % (off, chunk.hex(), q), flush=True)
    return d


c = C(HOST, PORT)

print("\n== 1) reserve 边界 ==", flush=True)
for res in [512, 513, 600, 768, 1024, 1023]:
    c.delete(0)
    r = c.create(0, "t", res, 0, "")
    ok = b"ok" in r
    cap = None
    if ok:
        cap = parse(c.show(0))
    print("  reserve=%-5d ok=%s cap=%s" % (res, ok, cap[:2] if cap else None), flush=True)
c.delete(0)

print("\n== 2) 布局探针 ==", flush=True)
c.create(0, "A", 512, 512, "41" * 512)
annotate("A fresh", c.show(0))
c.pack(0)
annotate("A packed", c.show(0))
c.create(1, "B", 32, 32, "42" * 32)
c.create(2, "C", 32, 32, "43" * 32)
c.create(3, "D", 32, 32, "44" * 32)
annotate("A after BCD", c.show(0))
annotate("B", c.show(1))
annotate("C", c.show(2))
annotate("D", c.show(3))
c.s.close()