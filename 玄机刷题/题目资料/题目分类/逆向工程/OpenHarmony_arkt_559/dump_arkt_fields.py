"""Print class and field records from the local Ark ABC, without modifying it."""
from pathlib import Path
import struct
from parse_arkt_abc_methods import string_at, skip_class_data, uleb


def sleb(data, pos):
    result = shift = 0
    while True:
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            if shift < 32 and byte & 0x40:
                result |= -(1 << shift)
            return result, pos


def main():
    data = Path(r"附件解包\HAP内容\ets\modules.abc").read_bytes()
    count, index_off = struct.unpack_from("<II", data, 0x1C)
    offsets = [struct.unpack_from("<I", data, index_off + 4*i)[0] for i in range(count)]
    for ci, class_off in enumerate(offsets):
        pos = class_off
        name, pos = string_at(data, pos)
        super_off = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        access, pos = uleb(data, pos)
        nf, nm, = 0, 0
        nf, pos = uleb(data, pos)
        nm, pos = uleb(data, pos)
        pos = skip_class_data(data, pos)
        print(f"CLASS[{ci}] name={name!r} off=0x{class_off:x} super=0x{super_off:x} access=0x{access:x} fields={nf} methods={nm}")
        for fi in range(nf):
            rec = pos
            class_idx, type_idx = struct.unpack_from("<HH", data, pos)
            name_off = struct.unpack_from("<I", data, pos+4)[0]
            pos += 8
            flags, pos = uleb(data, pos)
            fname, _ = string_at(data, name_off)
            tags = []
            while True:
                tag = data[pos]
                pos += 1
                if tag == 0:
                    break
                if tag == 1:
                    v, pos = sleb(data, pos)
                    tags.append((tag, v))
                elif tag in (2, 3, 4, 5, 6, 7):
                    v = struct.unpack_from("<I", data, pos)[0]
                    raw = data[pos:pos+4]
                    pos += 4
                    tags.append((tag, v, raw.hex()))
                else:
                    raise ValueError(f"unknown field tag 0x{tag:02x} at 0x{pos-1:x}")
            print(f"  FIELD[{fi}] rec=0x{rec:x} name_off=0x{name_off:x} name={fname!r} class_idx={class_idx} type_idx={type_idx} flags=0x{flags:x} data={tags!r}")


if __name__ == "__main__":
    main()
