#!/usr/bin/env python3
"""Dump selected OpenHarmony Panda literal arrays from modules.abc.

The decoding follows the LiteralTag values and literal-array index described by
the OpenHarmony Panda file format.  This is a small inspection helper for the
challenge attachment, not a general purpose Ark disassembler.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path


DATA = Path(sys.argv[1]).read_bytes()


def panda_string(offset: int) -> str:
    pos = offset
    shift = 0
    length_tag = 0
    while True:
        byte = DATA[pos]
        pos += 1
        length_tag |= (byte & 0x7F) << shift
        if byte < 0x80:
            break
        shift += 7
    end = DATA.index(b"\x00", pos)
    return DATA[pos:end].decode("utf-8", "replace")


def dump_array(index: int) -> list[str]:
    count_arrays = struct.unpack_from("<I", DATA, 0x2C)[0]
    array_index_off = struct.unpack_from("<I", DATA, 0x30)[0]
    if not 0 <= index < count_arrays:
        raise ValueError(f"literalarray index {index:#x} out of range ({count_arrays})")
    array_off = struct.unpack_from("<I", DATA, array_index_off + index * 4)[0]
    count = struct.unpack_from("<I", DATA, array_off)[0]
    pos = array_off + 4
    result: list[str] = []

    for item in range(count):
        tag = DATA[pos]
        pos += 1
        if tag == 0x00:  # tag-value / signed 8-bit integer
            value = struct.unpack_from("<b", DATA, pos)[0]
            pos += 1
            desc = f"i8 {value}"
        elif tag == 0x01:  # bool
            value = DATA[pos]
            pos += 1
            desc = f"bool {bool(value)}"
        elif tag == 0x02:  # 32-bit integer
            value = struct.unpack_from("<I", DATA, pos)[0]
            pos += 4
            desc = f"integer {value} ({value:#x})"
        elif tag == 0x03:
            value = struct.unpack_from("<f", DATA, pos)[0]
            pos += 4
            desc = f"float {value}"
        elif tag == 0x04:
            value = struct.unpack_from("<d", DATA, pos)[0]
            pos += 8
            desc = f"double {value}"
        elif tag == 0x05:  # file offset to Panda String
            string_off = struct.unpack_from("<I", DATA, pos)[0]
            pos += 4
            desc = f"string @{string_off:#x} {panda_string(string_off)!r}"
        elif tag in (0x06, 0x07, 0x16, 0x18, 0x1C):
            value = struct.unpack_from("<I", DATA, pos)[0]
            pos += 4
            desc = f"reference {value:#x}"
        elif tag == 0x09:
            value = struct.unpack_from("<H", DATA, pos)[0]
            pos += 2
            desc = f"method-affiliate {value:#x}"
        elif tag in (0x08, 0x19, 0x1A, 0x1B, 0xFF):
            value = DATA[pos]
            pos += 1
            desc = f"tag {tag:#x} value {value:#x}"
        elif 0x0A <= tag <= 0x15:
            value = struct.unpack_from("<I", DATA, pos)[0]
            pos += 4
            desc = f"array-data @{value:#x}"
            # Typed arrays are stored as a single data block; its first entry
            # consumes the remaining logical values in this literal array.
            result.append(f"  [{item:02}] tag={tag:#04x} {desc}")
            break
        elif tag == 0x17:
            value = struct.unpack_from("<I", DATA, pos)[0]
            pos += 4
            desc = f"literal-buffer-index {value:#x}"
        else:
            raise ValueError(f"unknown literal tag {tag:#x} at file offset {pos - 1:#x}")
        result.append(f"  [{item:02}] tag={tag:#04x} {desc}")

    return [f"array {index:#x} @ {array_off:#x} literals={count}", *result]


if __name__ == "__main__":
    for value in sys.argv[2:]:
        index = int(value, 0)
        for line in dump_array(index):
            print(line)
