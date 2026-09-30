"""临时脚本（用完即删）：解 514 的 PoW 网关，并打印后续交互。"""
import hashlib
import itertools
import re
import socket
import string
import time

HOST, PORT = "env.xj.edisec.net", 31888


def recv_until(s, marker=b": ", timeout=5.0):
    s.settimeout(0.3)
    buf = b""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            d = s.recv(4096)
        except socket.timeout:
            continue
        if not d:
            break
        buf += d
        if marker in buf:
            break
    return buf


def solve_pow(md5hex, masked):
    """masked 形如 ____wWpoSZ：把下划线位置补成 A-Z 暴力枚举。"""
    hidden = masked.count("_")
    pos = [i for i, ch in enumerate(masked) if ch == "_"]
    fixed = list(masked)
    for combo in itertools.product(string.ascii_uppercase, repeat=hidden):
        for i, ch in zip(pos, combo):
            fixed[i] = ch
        cand = "".join(fixed)
        if hashlib.md5(cand.encode()).hexdigest() == md5hex:
            return "".join(combo), cand
    return None, None


s = socket.create_connection((HOST, PORT), timeout=6)
banner = recv_until(s)
print("banner:", repr(banner))

m_tok = re.search(rb"Token:\s*([A-Za-z_]+)", banner)
m_md5 = re.search(rb"MD5:\s*([0-9a-f]{32})", banner)
masked = m_tok.group(1).decode()
md5hex = m_md5.group(1).decode()
print("masked =", masked, "md5 =", md5hex)

t0 = time.time()
answer, full = solve_pow(md5hex, masked)
print("brute force %.2fs -> missing=%s full=%s" % (time.time() - t0, answer, full))

s.sendall(answer.encode() + b"\n")
time.sleep(1.0)
resp = recv_until(s, marker=b"> ", timeout=6.0)
print("stage1 resp:", repr(resp[:1200]))
s.close()