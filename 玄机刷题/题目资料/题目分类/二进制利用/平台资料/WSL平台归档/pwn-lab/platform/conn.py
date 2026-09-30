#!/usr/bin/env python3
import socket, sys, time
HOST = sys.argv[1] if len(sys.argv) > 1 else "env.xj.edisec.net"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 30410
for att in range(5):
    try:
        s = socket.create_connection((HOST, PORT), timeout=8)
        s.settimeout(3)
        buf = b""
        try:
            while True:
                d = s.recv(4096)
                if not d:
                    break
                buf += d
                if b"Enter" in buf:
                    break
        except socket.timeout:
            pass
        print("att%d len=%d %r" % (att, len(buf), buf[:300]), flush=True)
        s.close()
    except Exception as e:
        print("att%d ERR %r" % (att, e), flush=True)
    time.sleep(1)