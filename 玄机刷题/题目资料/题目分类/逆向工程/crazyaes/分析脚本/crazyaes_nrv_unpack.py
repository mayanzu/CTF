from pathlib import Path
import hashlib
import struct

source_path = Path(__file__).resolve().parents[1] / '附件' / 'crazyaes.exe'
output_path = Path(__file__).resolve().parents[1] / '分析产物' / 'crazyaes-unpacked-section.bin'
image = source_path.read_bytes()
stream = image[0x400:0x26800]
si = 0
bitbuf = 0
memory = bytearray(0xA5000)
di = 0
last_ebp = 0xFFFFFFFF
mask = 0xFFFFFFFF
steps = 0
entry_logged = False
entry_logged = False


def read_u32():
    global si
    chunk = stream[si:si + 4]
    if len(chunk) < 4:
        chunk += bytes(4 - len(chunk))
    si += 4
    return struct.unpack('<I', chunk)[0]


def read_byte():
    global si
    value = stream[si] if si < len(stream) else 0
    si += 1
    return value


def shift_bit():
    global bitbuf
    bit = (bitbuf >> 31) & 1
    bitbuf = (bitbuf << 1) & mask
    return bit, bitbuf == 0


def refill_adc():
    global bitbuf
    word = read_u32()
    bit = (word >> 31) & 1
    bitbuf = ((word << 1) | 1) & mask
    return bit


def next_bit():
    bit, zero = shift_bit()
    if zero:
        return refill_adc()
    return bit


def signed32(value):
    value &= mask
    return value if value < 0x80000000 else value - 0x100000000


def ensure(pos, count=1):
    needed = pos + count
    if needed > len(memory):
        if needed > 0x100000:
            raise RuntimeError(f'output exceeded safety bound: need={needed:#x}, di={di:#x}')
        memory.extend(bytes(needed - len(memory) + 0x1000))


def decode_offset_code():
    global bitbuf
    eax = 1
    eax = ((eax << 1) + next_bit()) & mask
    while True:
        bit, zero = shift_bit()
        if bit == 0:
            eax = (eax - 1) & mask
            eax = ((eax << 1) + next_bit()) & mask
            eax = ((eax << 1) + next_bit()) & mask
            continue
        if not zero:
            return eax
        if refill_adc():
            return eax
        eax = (eax - 1) & mask
        eax = ((eax << 1) + next_bit()) & mask
        eax = ((eax << 1) + next_bit()) & mask


def decode_length(ebp):
    global bitbuf
    ecx = 0
    bit = next_bit()
    if bit:
        ecx = ((ecx << 1) + 1) & mask
    else:
        ecx += 1
        bit = next_bit()
        if bit:
            ecx = ((ecx << 1) + 1) & mask
        else:
            while True:
                ecx = ((ecx << 1) + next_bit()) & mask
                bit, zero = shift_bit()
                if bit == 0:
                    continue
                if not zero:
                    break
                if refill_adc():
                    break
            ecx = (ecx + 2) & mask
    extra = 1 if (ebp & mask) < 0xFFFFFB00 else 0
    return (ecx + 2 + extra) & mask


def copy_match(ebp, length):
    global di
    distance = signed32(ebp)
    if length > 0x95000 or di + length > 0xA5000:
        raise RuntimeError(f'invalid match length={length:#x}, di={di:#x}, ebp={distance}')
    if distance > -4:
        for _ in range(length):
            src = di + distance
            if src < 0:
                raise RuntimeError(f'negative back-reference source={src}, di={di}, distance={distance}')
            ensure(max(di, src))
            memory[di] = memory[src]
            di += 1
        return
    remaining = length
    while True:
        src = di + distance
        if src < 0:
            raise RuntimeError(f'negative back-reference source={src}, di={di}, distance={distance}')
        ensure(max(di, src), 4)
        memory[di:di + 4] = memory[src:src + 4]
        di += 4
        remaining = (remaining - 4) & mask
        if not (remaining > 0):
            break
    di = (di + remaining) & mask


while steps < 2000000:
    steps += 1
    if next_bit():
        ensure(di)
        memory[di] = read_byte()
        di += 1
        continue

    code = decode_offset_code()
    eax = (code - 3) & mask
    if code < 3:
        ebp = last_ebp
        # Short/repeat-offset length path at 4bbfbb..4bbffb.
        ecx = 0
        bit = next_bit()
        if bit:
            ecx = ((ecx << 1) + 1) & mask
            length = (ecx + 2 + (1 if (ebp & mask) < 0xFFFFFB00 else 0)) & mask
        else:
            ecx += 1
            bit = next_bit()
            if bit:
                ecx = ((ecx << 1) + 1) & mask
                length = (ecx + 2 + (1 if (ebp & mask) < 0xFFFFFB00 else 0)) & mask
            else:
                while True:
                    ecx = ((ecx << 1) + next_bit()) & mask
                    bit, zero = shift_bit()
                    if bit == 0:
                        continue
                    if not zero:
                        break
                    if refill_adc():
                        break
                ecx = (ecx + 2) & mask
                length = (ecx + 2 + (1 if (ebp & mask) < 0xFFFFFB00 else 0)) & mask
    else:
        eax = (eax << 8) & mask
        eax = (eax & 0xFFFFFF00) | read_byte()
        eax ^= mask
        if eax == 0:
            break
        ebp = (signed32(eax) >> 1) & mask
        last_ebp = ebp
        length = decode_length(ebp)

    if steps <= 12:
        print(f'match#{steps}: out={di:#x} code={code:#x} ebp={signed32(ebp)} len={length}')
    copy_match(ebp, length)
    if di >= 0x32180 and not entry_logged:
        print("entrypoint_window=" + memory[0x32150:0x32180].hex().upper())
        print("pointer_at_entry_window=0x%X" % di)
        output_path.write_bytes(memory[:di])
        entry_logged = True
else:
    raise RuntimeError('command limit reached before end marker')

unpacked = bytes(memory[:di])
output_path.write_bytes(unpacked)
print(f'end_marker=True')
print(f'steps={steps}')
print(f'compressed_consumed={si} of {len(stream)}')
print(f'output_pointer=0x{di:x} ({di} bytes)')
print(f'expected_virtual_size=0x95000 (610304 bytes)')
print(f'output_sha256={hashlib.sha256(unpacked).hexdigest().upper()}')
print(f'output_head={unpacked[:32].hex(" ").upper()}')
print(f'output_file={output_path}')




