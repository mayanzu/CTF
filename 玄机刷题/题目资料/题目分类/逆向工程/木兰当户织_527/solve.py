#!/usr/bin/env python3
"""Extract and decode the Base64 flag embedded in challenge #527's PE file."""

from __future__ import annotations

import argparse
import base64
from pathlib import Path


DATA_OFFSET = 0x2400  # .rdata string file offset, confirmed by strings -t x and objdump.


def main() -> None:
    default_exe = Path(__file__).parent / "附件" / "唧唧复唧唧，木兰当户织.exe"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("exe", nargs="?", type=Path, default=default_exe)
    args = parser.parse_args()

    data = args.exe.read_bytes()
    if len(data) <= DATA_OFFSET:
        raise SystemExit(f"文件太短，无法读取偏移 0x{DATA_OFFSET:x}: {args.exe}")

    end = data.find(b"\0", DATA_OFFSET)
    if end < 0:
        raise SystemExit("Base64 常量后未找到 NUL 终止符")

    encoded_bytes = data[DATA_OFFSET:end]
    encoded = encoded_bytes.decode("ascii")
    flag_bytes = base64.b64decode(encoded, validate=True)
    flag = flag_bytes.decode("ascii")
    if base64.b64encode(flag_bytes).decode("ascii") != encoded:
        raise SystemExit("Base64 往返校验失败")

    print("Source: challenge EXE")
    print(f"File length: {len(data)} bytes")
    print(f"Base64 file offset: 0x{DATA_OFFSET:x}")
    print(f"Base64 source: {encoded}")
    print(f"Decoded flag: {flag}")
    print("Base64 round-trip: PASS")


if __name__ == "__main__":
    main()
