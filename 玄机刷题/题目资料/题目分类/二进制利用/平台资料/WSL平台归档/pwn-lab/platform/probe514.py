"""临时探针（用完即删）：探测 514 实例的服务形态。"""
import socket
import time

HOST, PORT = "env.xj.edisec.net", 31888
s = socket.create_connection((HOST, PORT), timeout=6)
s.settimeout(2.5)
buf = b""
try:
    for _ in range(4):
        d = s.recv(4096)
        if not d:
            break
        buf += d
except Exception as e:
    buf += ("<recv-timeout %s>" % type(e).__name__).encode()
print("banner:", repr(buf[:800]))

for probe in (b"\n", b"help\n", b"1\n"):
    try:
        s.sendall(probe)
        time.sleep(0.8)
        d = s.recv(4096)
        print("send %r ->" % probe, repr(d[:400]))
    except Exception as e:
        print("send %r err:" % probe, repr(e))
s.close()