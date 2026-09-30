from __future__ import annotations

import hashlib
import struct
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ZIP_PATH = ROOT / 'originals' / 'are_you_ok.zip'
EXE_PATH = ROOT / 'extracted' / '你好吗.exe'
MASK32 = 0xFFFFFFFF


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from('<H', data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from('<I', data, off)[0]


def cstring(data: bytes, off: int) -> bytes:
    end = data.find(b'\0', off)
    return data[off:] if end < 0 else data[off:end]


def parse_pe(data: bytes):
    assert data[:2] == b'MZ', 'DOS signature missing'
    peoff = u32(data, 0x3C)
    assert data[peoff:peoff + 4] == b'PE\0\0', 'PE signature missing'
    coff = peoff + 4
    machine = u16(data, coff)
    section_count = u16(data, coff + 2)
    symbol_ptr = u32(data, coff + 8)
    symbol_count = u32(data, coff + 12)
    optional_size = u16(data, coff + 16)
    optional = coff + 20
    magic = u16(data, optional)
    assert magic == 0x20B, f'Expected AMD64 PE32+, got 0x{magic:04x}'
    image_base = struct.unpack_from('<Q', data, optional + 24)[0]
    entry_rva = u32(data, optional + 16)
    subsystem = u16(data, optional + 68)
    num_dirs = u32(data, optional + 108)
    dirs_off = optional + 112
    dirs = [struct.unpack_from('<II', data, dirs_off + i * 8) for i in range(min(num_dirs, 16))]
    sections = []
    section_off = optional + optional_size
    for i in range(section_count):
        off = section_off + i * 40
        name = data[off:off + 8].split(b'\0', 1)[0].decode('ascii', 'replace')
        sections.append({
            'name': name,
            'vs': u32(data, off + 8),
            'va': u32(data, off + 12),
            'rs': u32(data, off + 16),
            'rp': u32(data, off + 20),
        })

    def rva_to_off(rva: int) -> int:
        if rva < u32(data, optional + 60):
            return rva
        for section in sections:
            span = max(section['vs'], section['rs'])
            if section['va'] <= rva < section['va'] + span:
                off = section['rp'] + rva - section['va']
                if off < len(data):
                    return off
        raise ValueError(f'Unmapped RVA 0x{rva:x}')

    # The PE retains its COFF symbol table. Parse it without a loader/decompiler.
    string_base = symbol_ptr + symbol_count * 18
    string_size = u32(data, string_base)
    string_table = data[string_base:string_base + string_size]
    symbols = {}
    index = 0
    while index < symbol_count:
        off = symbol_ptr + index * 18
        name_field = data[off:off + 8]
        if name_field[:4] == b'\0\0\0\0':
            string_offset = u32(data, off + 4)
            end = string_table.find(b'\0', string_offset)
            raw_name = string_table[string_offset:end if end >= 0 else len(string_table)]
        else:
            raw_name = name_field.split(b'\0', 1)[0]
        try:
            name = raw_name.decode('ascii')
        except UnicodeDecodeError:
            name = raw_name.decode('utf-8', 'replace')
        value = u32(data, off + 8)
        section_number = struct.unpack_from('<h', data, off + 12)[0]
        aux_count = data[off + 17]
        if section_number > 0 and section_number <= len(sections):
            section = sections[section_number - 1]
            if section['name'] == '.text':
                symbols[name] = section['va'] + value
        index += 1 + aux_count

    runtime_functions = {}
    if len(dirs) > 3 and dirs[3][0] and dirs[3][1]:
        pdata_rva, pdata_size = dirs[3]
        pdata_off = rva_to_off(pdata_rva)
        for pos in range(0, pdata_size - 11, 12):
            begin, end, unwind = struct.unpack_from('<III', data, pdata_off + pos)
            runtime_functions[begin] = (end, unwind)

    return {
        'machine': machine,
        'section_count': section_count,
        'image_base': image_base,
        'entry_rva': entry_rva,
        'subsystem': subsystem,
        'dirs': dirs,
        'sections': sections,
        'rva_to_off': rva_to_off,
        'symbols': symbols,
        'runtime_functions': runtime_functions,
    }


def mov_rbp_immediates(code: bytes) -> dict[int, int]:
    """Extract `mov dword ptr [rbp+disp8], imm32` encodings in this function."""
    found = {}
    for pos in range(len(code) - 7):
        if code[pos:pos + 2] == b'\xC7\x45':
            disp = struct.unpack_from('<b', code, pos + 2)[0]
            imm = u32(code, pos + 3)
            found[disp] = imm
    return found


def tea_f(value: int, ka: int, kb: int, total: int) -> int:
    return ((((value << 4) + ka) & MASK32)
            ^ ((value + total) & MASK32)
            ^ (((value >> 5) + kb) & MASK32))


def tea_decrypt(block: bytes, key: list[int], delta: int, rounds: int) -> bytes:
    v0, v1 = struct.unpack('<2I', block)
    total = (delta * rounds) & MASK32
    for _ in range(rounds):
        v1 = (v1 - tea_f(v0, key[2], key[3], total)) & MASK32
        v0 = (v0 - tea_f(v1, key[0], key[1], total)) & MASK32
        total = (total - delta) & MASK32
    return struct.pack('<2I', v0, v1)


def tea_encrypt(block: bytes, key: list[int], delta: int, rounds: int) -> bytes:
    v0, v1 = struct.unpack('<2I', block)
    total = 0
    for _ in range(rounds):
        total = (total + delta) & MASK32
        v0 = (v0 + tea_f(v1, key[0], key[1], total)) & MASK32
        v1 = (v1 + tea_f(v0, key[2], key[3], total)) & MASK32
    return struct.pack('<2I', v0, v1)


def main() -> None:
    exe = EXE_PATH.read_bytes()
    with zipfile.ZipFile(ZIP_PATH) as archive:
        entries = archive.infolist()
        assert len(entries) == 1, f'Expected one ZIP entry, got {len(entries)}'
        member = archive.read(entries[0])
        member_name = entries[0].filename
        compression = entries[0].compress_type
    assert member == exe, 'ZIP member bytes differ from extracted executable'

    pe = parse_pe(exe)
    names = {
        'sub_100': '_Z7sub_100Pci',
        'sub_101': '_Z7sub_101PjS_',
        'sub_102': '_Z7sub_102Pc',
        'main': 'main',
    }
    function_rvas = {label: pe['symbols'][symbol] for label, symbol in names.items()}
    function_codes = {}
    for label, rva in function_rvas.items():
        end, _unwind = pe['runtime_functions'][rva]
        off = pe['rva_to_off'](rva)
        function_codes[label] = exe[off:off + end - rva]

    main_code = function_codes['main']
    chunks = []
    cursor = 0
    while cursor + 10 <= len(main_code):
        if main_code[cursor:cursor + 2] == b'\x48\xB8':  # movabs rax, imm64
            raw = main_code[cursor + 2:cursor + 10]
            if all(byte in b'0123456789abcdefABCDEF' for byte in raw):
                chunks.append(raw)
            cursor += 10
        else:
            cursor += 1
    ciphertext_hex = b''.join(chunks).decode('ascii')
    assert len(chunks) == 8 and len(ciphertext_hex) == 64, 'Unexpected embedded hex literal layout'
    ciphertext = bytes.fromhex(ciphertext_hex)

    key_moves = mov_rbp_immediates(main_code)
    key_disps = (-16, -12, -8, -4)
    assert all(d in key_moves for d in key_disps), 'Could not recover four key words from main'
    key = [key_moves[d] for d in key_disps]

    tea_code = function_codes['sub_101']
    tea_moves = mov_rbp_immediates(tea_code)
    delta = tea_moves[-20]  # [rbp-0x14]
    initial_sum = tea_moves[-12]  # [rbp-0x0c]
    cmp = tea_code.find(b'\x83\x7D\xF0')  # cmp dword ptr [rbp-0x10], imm8
    assert cmp >= 0, 'TEA loop-counter compare not found'
    rounds = tea_code[cmp + 3] + 1  # cmp counter, 31; branch is jbe => 32 passes
    assert initial_sum == (delta * rounds) & MASK32
    assert key_moves.get(4) == 0x16, 'Final XOR immediate 0x16 not found in stack local'
    xor_byte = 0x16

    format_rva = 0x4000  # main passes .rdata at image VA 0x404000 to sscanf
    format_text = cstring(exe, pe['rva_to_off'](format_rva)).decode('ascii')
    assert format_text == '%2hhx', f'Unexpected sscanf format: {format_text!r}'

    decrypted_padded = b''.join(
        tea_decrypt(ciphertext[i:i + 8], key, delta, rounds)
        for i in range(0, len(ciphertext), 8)
    )
    assert len(ciphertext) % 8 == 0
    reencrypted = b''.join(
        tea_encrypt(decrypted_padded[i:i + 8], key, delta, rounds)
        for i in range(0, len(decrypted_padded), 8)
    )
    assert reencrypted == ciphertext, 'TEA re-encryption check failed'

    # Match sub_102: strlen, signed-char final byte, NUL at length - final_byte.
    c_length = decrypted_padded.find(b'\0')
    if c_length < 0:
        c_length = len(decrypted_padded)
    last = decrypted_padded[c_length - 1]
    signed_last = last if last < 0x80 else last - 0x100
    cut = c_length - signed_last
    assert 0 <= cut <= c_length, 'Observed signed padding length would index outside the C string'
    trimmed = decrypted_padded[:cut]
    result = bytes(byte ^ xor_byte for byte in trimmed)
    flag = result.decode('ascii')

    print(f'ZIP={ZIP_PATH}')
    print(f'ZIP_SHA256={sha256(ZIP_PATH.read_bytes())}')
    print(f'ZIP_MEMBER={member_name} size={len(member)} compression_method={compression}')
    print(f'EXE={EXE_PATH}')
    print(f'EXE_SIZE={len(exe)} EXE_SHA256={sha256(exe)}')
    print(f'ZIP_MEMBER_IDENTICAL_TO_EXE={member == exe}')
    print(f'PE_MACHINE=0x{pe["machine"]:04x} PE32+=True sections={pe["section_count"]} image_base=0x{pe["image_base"]:x} entry_rva=0x{pe["entry_rva"]:x} subsystem={pe["subsystem"]}')
    for label in ('main', 'sub_100', 'sub_101', 'sub_102'):
        rva = function_rvas[label]
        end = pe['runtime_functions'][rva][0]
        print(f'FUNCTION_{label}=RVA 0x{rva:x}..0x{end:x}')
    print(f'SSCANF_FORMAT={format_text!r}; encoded_input_hex_length={len(ciphertext_hex)}')
    print(f'CIPHERTEXT_HEX={ciphertext_hex}')
    print('TEA_KEY_WORDS=' + ','.join(f'0x{x:08x}' for x in key))
    print(f'TEA_DELTA=0x{delta:08x} rounds={rounds} initial_sum=0x{initial_sum:08x} final_xor=0x{xor_byte:02x}')
    print(f'DECRYPTED_32_BYTES_HEX={decrypted_padded.hex()}')
    print(f'DECRYPTED_32_BYTES_REPR={decrypted_padded!r}')
    print(f'REENCRYPTION_MATCHES_CIPHERTEXT={reencrypted == ciphertext}')
    print(f'C_STRING_LENGTH={c_length}; final_byte=0x{last:02x} signed_final_byte={signed_last}; trim_offset={cut}')
    print(f'TRIMMED_BEFORE_XOR={trimmed.decode("ascii")!r}')
    print(f'FINAL_ASCII={flag}')


if __name__ == '__main__':
    main()
