from pathlib import Path
import struct
import sys

source = Path(sys.argv[1])
data = source.read_bytes()
signature = b"\x89PNG\r\n\x1a\n"
starts = [i for i in range(len(data)) if data.startswith(signature, i)]
for index, start in enumerate(starts, 1):
    pos = start + len(signature)
    chunks = []
    width = height = None
    while pos + 12 <= len(data):
        length = struct.unpack_from(">I", data, pos)[0]
        kind = data[pos + 4:pos + 8]
        end = pos + 12 + length
        if end > len(data):
            raise ValueError(f"chunk overruns file at 0x{pos:x}")
        if kind == b"IHDR":
            width, height = struct.unpack_from(">II", data, pos + 8)
        chunks.append(kind.decode("ascii", "replace"))
        pos = end
        if kind == b"IEND":
            break
    if not chunks or chunks[-1] != "IEND":
        continue
    out = source.with_name(f"embedded_{index}_{width}x{height}.png")
    out.write_bytes(data[start:pos])
    print(f"image={out} offset=0x{start:x} size={pos-start} dimensions={width}x{height} chunks={chunks}")
