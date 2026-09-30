"""Minimal, read-only parser for the local Ark ABC class/method metadata."""
from __future__ import annotations

import argparse
import struct
from pathlib import Path


def uleb(data: bytes, pos: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7


def string_at(data: bytes, pos: int) -> tuple[str, int]:
    encoded_len, pos = uleb(data, pos)
    length = encoded_len >> 1
    raw = data[pos:pos + length]
    end = pos + length
    # The files used here store ordinary ASCII names and UTF-8 literals.
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")
    return text, end + 1  # trailing NUL


def skip_class_data(data: bytes, pos: int) -> int:
    while True:
        tag = data[pos]
        pos += 1
        if tag == 0:
            return pos
        if tag == 1:
            count, pos = uleb(data, pos)
            pos += count * 2
        elif tag == 2:
            pos += 1
        elif 3 <= tag <= 7:
            pos += 4
        else:
            raise ValueError(f"unknown class tag 0x{tag:02x} at 0x{pos - 1:x}")


def skip_field_data(data: bytes, pos: int) -> int:
    while True:
        tag = data[pos]
        pos += 1
        if tag == 0:
            return pos
        if tag == 1:  # SLEB128 field value
            while data[pos] & 0x80:
                pos += 1
            pos += 1
        elif 2 <= tag <= 6:
            pos += 4
        else:
            raise ValueError(f"unknown field tag 0x{tag:02x} at 0x{pos - 1:x}")


def method_tags(data: bytes, pos: int) -> tuple[int | None, int]:
    code_off = None
    while True:
        tag = data[pos]
        pos += 1
        if tag == 0:
            return code_off, pos
        if tag == 1:
            code_off = struct.unpack_from("<I", data, pos)[0]
            pos += 4
        elif tag == 2:
            pos += 1
        elif 3 <= tag <= 9:
            pos += 4
        else:
            raise ValueError(f"unknown method tag 0x{tag:02x} at 0x{pos - 1:x}")


def parse_code_header(data: bytes, code_off: int) -> tuple[int, int, int, int, int]:
    pos = code_off
    num_vregs, pos = uleb(data, pos)
    num_args, pos = uleb(data, pos)
    code_size, pos = uleb(data, pos)
    tries_size, pos = uleb(data, pos)
    return num_vregs, num_args, code_size, tries_size, pos


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("abc", nargs="?", default=r"附件解包\HAP内容\ets\modules.abc")
    args = ap.parse_args()
    data = Path(args.abc).read_bytes()
    nclasses = struct.unpack_from("<I", data, 0x1C)[0]
    class_index_off = struct.unpack_from("<I", data, 0x20)[0]
    nregions = struct.unpack_from("<I", data, 0x34)[0]
    region_index_off = struct.unpack_from("<I", data, 0x38)[0]
    print(f"FILE_SIZE={len(data)} NUM_CLASSES={nclasses} CLASS_INDEX=0x{class_index_off:x}")
    print(f"NUM_REGIONS={nregions} REGION_INDEX=0x{region_index_off:x}")
    for region_no in range(nregions):
        roff = region_index_off + region_no * 40
        fields = struct.unpack_from("<10I", data, roff)
        print("REGION", region_no, "fields=", [f"0x{x:x}" for x in fields])
    classes = [struct.unpack_from("<I", data, class_index_off + 4 * i)[0] for i in range(nclasses)]
    for ci, coff in enumerate(classes):
        pos = coff
        cname, pos = string_at(data, pos)
        super_off = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        access, pos = uleb(data, pos)
        nfields, pos = uleb(data, pos)
        nmethods, pos = uleb(data, pos)
        pos = skip_class_data(data, pos)
        for _ in range(nfields):
            pos += 4  # class_idx + type_idx
            fname_off = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            fflags, pos = uleb(data, pos)
            fname, _ = string_at(data, fname_off)
            pos = skip_field_data(data, pos)
        print(f"CLASS[{ci}] off=0x{coff:x} name={cname!r} super=0x{super_off:x} access=0x{access:x} fields={nfields} methods={nmethods}")
        for mi in range(nmethods):
            mstart = pos
            class_idx, proto_idx = struct.unpack_from("<HH", data, pos)
            name_off = struct.unpack_from("<I", data, pos + 4)[0]
            pos += 8
            flags, pos = uleb(data, pos)
            code_off, pos = method_tags(data, pos)
            mname, _ = string_at(data, name_off)
            if code_off is None:
                print(f"  METHOD[{mi}] rec=0x{mstart:x} name={mname!r} class_idx={class_idx} proto_idx={proto_idx} access=0x{flags:x} code=None")
            else:
                try:
                    regs, argc, size, tries, insn_off = parse_code_header(data, code_off)
                    code_meta = f"code=0x{code_off:x} regs={regs} args={argc} insn_size={size} tries={tries} insn=0x{insn_off:x}"
                except Exception as exc:
                    code_meta = f"code=0x{code_off:x} header_error={type(exc).__name__}:{exc}"
                print(f"  METHOD[{mi}] rec=0x{mstart:x} name={mname!r} class_idx={class_idx} proto_idx={proto_idx} access=0x{flags:x} {code_meta}")


if __name__ == "__main__":
    main()
