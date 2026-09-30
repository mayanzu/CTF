"""Statically decode the NRV2B stream from the UPX stub; never executes PE code."""
from pathlib import Path
import struct
import sys

src_path = Path(sys.argv[1])
dst_path = Path(sys.argv[2])
data = src_path.read_bytes()
src = 0x21D  # UPX entry's RSI = image RVA 0xc01d; raw upx1 starts at 0x200.
bitbuf = 0
out = bytearray()
last_distance = 1  # stub starts with RBP = -1.
matches = literals = 0
MAX_OUT = 0x100000

def read_byte():
    global src
    if src >= len(data):
        raise EOFError(f"input exhausted at file offset 0x{src:x}")
    b = data[src]
    src += 1
    return b

def getbit():
    """Model the stub's ADD/ADC bit reader including its appended sentinel bit."""
    global bitbuf, src
    shifted = (bitbuf << 1) & 0xFFFFFFFF
    carry = (bitbuf >> 31) & 1
    if shifted == 0:
        if src + 4 > len(data):
            raise EOFError(f"bitstream exhausted at file offset 0x{src:x}")
        word = struct.unpack_from("<I", data, src)[0]
        src += 4
        carry = word >> 31
        bitbuf = ((word << 1) | 1) & 0xFFFFFFFF
    else:
        bitbuf = shifted
    return carry

while True:
    # Literal run: the stub copies one source byte for each leading 1 bit.
    while getbit():
        out.append(read_byte())
        literals += 1
        if len(out) > MAX_OUT:
            raise ValueError("output exceeded safety limit")

    # NRV2B offset prefix uses alternating data and continuation bits.
    code = 1
    while True:
        code = ((code << 1) | getbit()) & 0xFFFFFFFF
        if getbit():
            break

    if code == 2:
        distance = last_distance
    else:
        raw = ((((code - 3) & 0xFFFFFFFF) << 8) | read_byte()) & 0xFFFFFFFF
        if raw == 0xFFFFFFFF:
            break
        distance = raw + 1
        last_distance = distance

    # Two-bit short length; 00 selects the extended unary/binary length form.
    short = (getbit() << 1) | getbit()
    if short:
        length = short + 1
    else:
        value = 1
        while True:
            value = ((value << 1) | getbit()) & 0xFFFFFFFF
            if getbit():
                break
        length = value + 3
    if distance > 0xD00:
        length += 1
    if distance <= 0 or distance > len(out):
        raise ValueError(f"invalid back-reference distance={distance}, output={len(out)}")
    for _ in range(length):
        out.append(out[-distance])
    matches += 1
    if len(out) > MAX_OUT:
        raise ValueError("output exceeded safety limit")

dst_path.parent.mkdir(parents=True, exist_ok=True)
dst_path.write_bytes(out)
print(f"termination=NRV2B end marker")
print(f"input_start=0x21d input_end=0x{src:x} compressed_consumed={src-0x21d}")
print(f"output_size=0x{len(out):x} ({len(out)} bytes) literals={literals} matches={matches}")
print(f"output_path={dst_path}")
