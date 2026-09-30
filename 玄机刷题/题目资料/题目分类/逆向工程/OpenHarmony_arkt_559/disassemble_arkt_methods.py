"""Minimal local Ark ABC bytecode decoder based on the already-present ISA YAML."""
from __future__ import annotations

import argparse
import re
import struct
from pathlib import Path

import yaml

from parse_arkt_abc_methods import method_tags, parse_code_header, skip_class_data, skip_field_data, string_at, uleb


PREFIX_OPS = {"throw": 0xFE, "wide": 0xFD, "deprecated": 0xFC, "callruntime": 0xFB}


def isa_table(isa_path: Path):
    doc = yaml.safe_load(isa_path.read_text(encoding="utf-8"))
    table: dict[tuple[str | None, int], tuple[str, str]] = {}
    for group in doc["groups"]:
        for item in group.get("instructions", []):
            sig = item["sig"]
            mnemonic = sig.split()[0]
            ops = item.get("opcode_idx", [])
            fmts = item.get("format", [])
            for op, fmt in zip(ops, fmts):
                first = mnemonic.split(".", 1)[0]
                prefix = first if first in PREFIX_OPS else None
                if prefix is None and fmt.startswith("pref_") and mnemonic == "throw":
                    prefix = "throw"
                op = int(op, 0) if isinstance(op, str) else int(op)
                key = (prefix, op)
                if key in table:
                    raise ValueError(f"duplicate opcode {key}: {table[key]} vs {(sig, fmt)}")
                table[key] = (sig, fmt)
    return table


def decode_fields(fmt: str, raw: bytes, pos: int):
    if fmt.startswith("pref_op_"):
        spec = fmt[len("pref_op_"):]
    elif fmt.startswith("op_"):
        spec = fmt[len("op_"):]
    else:
        raise ValueError(f"unsupported format {fmt}")
    if spec == "none":
        return [], pos
    tokens = re.findall(r"(imm\d*|id\d*|v\d*)_(4|8|16|32|64)", spec)
    if "_".join(f"{name}_{bits}" for name, bits in tokens) != spec:
        raise ValueError(f"unsupported field layout {fmt}")
    out = []
    for name, bits_s in tokens:
        bits = int(bits_s)
        if bits == 4:
            if not out or out[-1][2] != "pending_nibble":
                byte = raw[pos]
                pos += 1
                out.append((name, byte & 0x0F, "pending_nibble"))
            else:
                byte = raw[pos - 1]
                out.append((name, (byte >> 4) & 0x0F, "nibble"))
                out[-2] = (out[-2][0], out[-2][1], "nibble")
            continue
        size = bits // 8
        value = int.from_bytes(raw[pos:pos + size], "little", signed=False)
        pos += size
        out.append((name, value, f"u{bits}"))
    return out, pos


def class_methods(data: bytes):
    nclasses = struct.unpack_from("<I", data, 0x1C)[0]
    index_off = struct.unpack_from("<I", data, 0x20)[0]
    offsets = [struct.unpack_from("<I", data, index_off + 4 * i)[0] for i in range(nclasses)]
    rows = []
    for ci, coff in enumerate(offsets):
        pos = coff
        cname, pos = string_at(data, pos)
        pos += 4
        _, pos = uleb(data, pos)  # access flags
        nfields, pos = uleb(data, pos)
        nmethods, pos = uleb(data, pos)
        pos = skip_class_data(data, pos)
        for _ in range(nfields):
            pos += 8
            _, pos = uleb(data, pos)
            pos = skip_field_data(data, pos)
        for mi in range(nmethods):
            rec = pos
            cidx, pidx = struct.unpack_from("<HH", data, pos)
            name_off = struct.unpack_from("<I", data, pos + 4)[0]
            pos += 8
            flags, pos = uleb(data, pos)
            code_off, pos = method_tags(data, pos)
            name, _ = string_at(data, name_off)
            rows.append({"class_index": ci, "class": cname, "method_index": mi,
                         "record": rec, "class_id": cidx, "proto_id": pidx,
                         "name": name, "flags": flags, "code_off": code_off})
    return rows


def resolve_string_id(data: bytes, method_id: int):
    region_count = struct.unpack_from("<I", data, 0x34)[0]
    region_off = struct.unpack_from("<I", data, 0x38)[0]
    for rn in range(region_count):
        fields = struct.unpack_from("<10I", data, region_off + rn * 40)
        start, end, _, _, count, index_off = fields[:6]
        if start <= method_id < end:
            return None
        # Indexes are shared by the methods in a region. A code ID points into
        # that region's method index; OpenHarmony's own disassembler uses this
        # same resolver before interpreting STRING_ID/METHOD_ID operands.
        if start <= method_id < end:
            raise AssertionError
    # This app has one code region; use its method-index table.
    fields = struct.unpack_from("<10I", data, region_off)
    count, index_off = fields[4], fields[5]
    if count <= 0:
        return None
    return [struct.unpack_from("<I", data, index_off + 4 * i)[0] for i in range(count)]


def decode_method(data: bytes, meta: dict, table: dict):
    off = meta["code_off"]
    regs, argc, code_size, tries, ip = parse_code_header(data, off)
    code = data[ip:ip + code_size]
    p = 0
    decoded = []
    while p < len(code):
        start = p
        op0 = code[p]
        p += 1
        prefix = None
        op = op0
        if op0 in PREFIX_OPS.values():
            prefix = next(k for k, v in PREFIX_OPS.items() if v == op0)
            if p >= len(code):
                raise ValueError(f"truncated prefix at +0x{start:x}")
            op = code[p]
            p += 1
        key = (prefix, op)
        if key not in table:
            raise ValueError(f"unknown opcode prefix={prefix!r} op=0x{op:02x} at +0x{start:x}; preceding={code[max(0,start-8):start].hex()}")
        sig, fmt = table[key]
        fields, p = decode_fields(fmt, code, p)
        decoded.append((start, p, sig, fields, code[start:p].hex()))
    if p != code_size:
        raise ValueError(f"decoded to {p} bytes, expected {code_size}")
    return regs, argc, code_size, tries, ip, decoded


def render(meta: dict, decoded, data: bytes, index_offsets: list[int], methods_by_offset: dict[int, str]):
    regs, argc, size, tries, ip, insns = decoded
    print(f"METHOD {meta['name']} class={meta['class']} rec=0x{meta['record']:x} code=0x{meta['code_off']:x} insn=0x{ip:x} vregs={regs} args={argc} size={size} tries={tries}")
    for rel, nxt, sig, fields, raw in insns:
        pieces = []
        id_kinds = iter(re.findall(r"\b(string_id|literalarray_id|method_id)\b", sig))
        for name, value, kind in fields:
            if kind == "pending_nibble":
                continue
            if name.startswith("id"):
                id_kind = next(id_kinds, "index")
                offset = index_offsets[value] if value < len(index_offsets) else None
                if offset is None:
                    detail = "<out-of-range>"
                elif id_kind == "string_id":
                    try:
                        value_text, _ = string_at(data, offset)
                        detail = f"0x{offset:x} {ascii(value_text)}"
                    except Exception as exc:
                        detail = f"0x{offset:x} <string error {type(exc).__name__}>"
                elif id_kind == "method_id":
                    detail = f"0x{offset:x} {methods_by_offset.get(offset, '<unresolved method>')}"
                else:
                    detail = f"0x{offset:x}"
                pieces.append(f"{name}={value} -> {id_kind} {detail}")
            else:
                pieces.append(f"{name}={value}")
        operands = " ".join(pieces)
        print(f"  {rel:04x} [{raw:<22}] {sig}{(' ' + operands) if operands else ''}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("abc", nargs="?", default=r"附件解包\HAP内容\ets\modules.abc")
    ap.add_argument("--isa", default=r"C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\OpenHarmony_easyre_560\analysis\reference\isa.yaml")
    ap.add_argument("--names", nargs="*", default=["enc", "handleCheck", "customBase64", "modPow", "rc4Encrypt", "rsaEncrypt", "stringToUint8Array"])
    args = ap.parse_args()
    data = Path(args.abc).read_bytes()
    table = isa_table(Path(args.isa))
    print(f"ABC={Path(args.abc).resolve()} SIZE={len(data)} OPCODE_FORMS={len(table)} ISA={Path(args.isa).resolve()}")
    methods = class_methods(data)
    index_offsets = resolve_string_id(data, 0)
    methods_by_offset = {m["record"]: m["name"] for m in methods}
    wanted = set(args.names)
    selected = [m for m in methods if m["class_index"] == 2 and m["code_off"] is not None
                and m["name"].split("#")[-1].split("^")[0] in wanted]
    print("SELECTED_METHODS", len(selected))
    for meta in selected:
        try:
            render(meta, decode_method(data, meta, table), data, index_offsets, methods_by_offset)
        except Exception as exc:
            print(f"ERROR method={meta['name']}: {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    main()
