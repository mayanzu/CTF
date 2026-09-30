from __future__ import annotations
import base64
import hashlib
import math
import struct
from pathlib import Path

ROOT = Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\OpenHarmony_arkt_559')
ABC = ROOT / '附件解包' / 'HAP内容' / 'ets' / 'modules.abc'
ZIP = ROOT / '附件' / 'arkt_platform_20260929.zip'
HAP = ROOT / '附件解包' / 'task_5.hap'
ARRAY_INDEX = 17
ARRAY_ADDRESS_FROM_CODE = 0x265A
RSA_N, RSA_E = 75067, 7
RSA_P, RSA_Q = 271, 277
RUNTIME_KEY = b'OHCTF2026'
STD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
CUSTOM_B64 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/'
EXPECTED_FLAG = b'flag{b80ebf0f0e210ad73664bdd19c16387e}'

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()

def read_uvar(data: bytes, cursor: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if cursor >= len(data):
            raise ValueError('unterminated variable-length integer')
        octet = data[cursor]
        cursor += 1
        result |= (octet & 0x7F) << shift
        if octet < 0x80:
            return result, cursor
        shift += 7
        if shift > 63:
            raise ValueError('variable-length integer overflow')

def string_at(data: bytes, offset: int) -> str:
    tagged_length, begin = read_uvar(data, offset)
    byte_length = tagged_length >> 1
    end = begin + byte_length
    if end >= len(data) or data[end] != 0:
        raise ValueError(f'bad terminated ABC string at {offset:#x}')
    return data[begin:end].decode('ascii', errors='strict')

def extract_target_strings(data: bytes) -> tuple[int, list[str], list[int]]:
    # The ABC header stores the literal-array count and its offset table at these fields.
    array_total = struct.unpack_from('<I', data, 0x2C)[0]
    array_index_table = struct.unpack_from('<I', data, 0x30)[0]
    if not (0 < array_total <= 100000 and 0 < array_index_table < len(data)):
        raise ValueError('implausible literal-array header values')
    if ARRAY_INDEX >= array_total:
        raise ValueError('target array index is outside the header table')
    array_offset = struct.unpack_from('<I', data, array_index_table + ARRAY_INDEX * 4)[0]
    if array_offset != ARRAY_ADDRESS_FROM_CODE:
        raise ValueError(f'constructor reference disagrees with header array index: {array_offset:#x}')
    slots = struct.unpack_from('<I', data, array_offset)[0]
    if slots != 76 or slots % 2:
        raise ValueError(f'unexpected LiteralArray slot count {slots}')
    cursor = array_offset + 4
    texts: list[str] = []
    offsets: list[int] = []
    for i in range(slots // 2):
        tag = data[cursor]
        cursor += 1
        value_offset = struct.unpack_from('<I', data, cursor)[0]
        cursor += 4
        if tag != 0x05:
            raise ValueError(f'item {i} tag {tag:#x}, expected STRING')
        texts.append(string_at(data, value_offset))
        offsets.append(value_offset)
    return array_offset, texts, offsets

def custom_b64_decode(token: str) -> bytes:
    back_map = {custom: standard for standard, custom in zip(STD_B64, CUSTOM_B64)}
    try:
        standard_token = ''.join('=' if char == '=' else back_map[char] for char in token)
    except KeyError as exc:
        raise ValueError(f'bad custom Base64 character {exc.args[0]!r}') from exc
    return base64.b64decode(standard_token.encode('ascii'), validate=True)

def custom_b64_encode(raw: bytes) -> str:
    forward_map = {standard: custom for standard, custom in zip(STD_B64, CUSTOM_B64)}
    standard_token = base64.b64encode(raw).decode('ascii')
    return ''.join('=' if char == '=' else forward_map[char] for char in standard_token)

def modular_inverse(a: int, modulus: int) -> int:
    old_r, r = a, modulus
    old_s, s = 1, 0
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    if old_r != 1:
        raise ValueError('RSA exponent has no inverse')
    return old_s % modulus

def rc4_style(data: bytes, key: bytes, subtract: bool) -> bytes:
    # Directly transcribed mathematical form of the Ark bytecode's variant:
    # KSA reads both S[j] and key[j % keylen]; PRGA output is +/- stream, not XOR.
    if not key:
        raise ValueError('empty key')
    box = list(range(256))
    j = 0
    for i in range(256):
        j = (j + box[j] + key[j % len(key)]) % 256
        box[i], box[j] = box[j], box[i]
    i = j = 0
    result = bytearray()
    for octet in data:
        i = (i + 1) % 256
        j = (j + box[i]) % 256
        box[i], box[j] = box[j], box[i]
        stream = box[(box[i] + box[j]) % 256]
        result.append((octet - stream if subtract else octet + stream) % 256)
    return bytes(result)

def main() -> None:
    for label, path in [('platform ZIP', ZIP), ('HAP', HAP), ('Ark ABC', ABC)]:
        print(f'{label} SHA256={sha256(path)} SIZE={path.stat().st_size}')
    abc = ABC.read_bytes()
    print('ABC_MAGIC=', abc[:8].hex(), 'FILE_SIZE=', len(abc))
    array_offset, targets, string_offsets = extract_target_strings(abc)
    print(f'LITERAL_ARRAY_TABLE_COUNT={struct.unpack_from("<I", abc, 0x2C)[0]} TABLE_OFFSET=0x{struct.unpack_from("<I", abc, 0x30)[0]:x}')
    print(f'ARRAY_INDEX={ARRAY_INDEX} ARRAY_OFFSET=0x{array_offset:x} RAW_SLOT_COUNT=76 TARGET_COUNT={len(targets)}')
    for i, (target, offset) in enumerate(zip(targets, string_offsets)):
        print(f'TARGET[{i:02d}] string_offset=0x{offset:x} token={target}')
    if len(targets) != 38:
        raise ValueError(f'expected exactly 38 strings, got {len(targets)}')

    cipher_integers: list[int] = []
    for i, token in enumerate(targets):
        raw = custom_b64_decode(token)
        numeric = raw.decode('ascii')
        if not numeric.isdecimal() or str(int(numeric)) != numeric:
            raise ValueError(f'target {i} is not canonical decimal ASCII: {raw!r}')
        cipher_integers.append(int(numeric))
        print(f'DECODE[{i:02d}] custom_b64={token} decimal={numeric}')

    phi = (RSA_P - 1) * (RSA_Q - 1)
    private_d = modular_inverse(RSA_E, phi)
    assert RSA_P * RSA_Q == RSA_N and math.gcd(RSA_E, phi) == 1 and private_d == 42583
    rsa_preimages = [pow(cipher, private_d, RSA_N) for cipher in cipher_integers]
    rsa_roundtrip = [pow(pre, RSA_E, RSA_N) for pre in rsa_preimages]
    if rsa_roundtrip != cipher_integers or any(x > 255 for x in rsa_preimages):
        raise ValueError('RSA inversion did not round-trip all 38 byte values')
    rsa_layer = bytes(rsa_preimages)
    flag = rc4_style(rsa_layer, RUNTIME_KEY, subtract=True)
    print(f'RSA={RSA_P}*{RSA_Q}={RSA_N}; phi={phi}; e={RSA_E}; d={private_d}')
    print(f'RSA_LAYER_COUNT={len(rsa_layer)} RSA_LAYER_HEX={rsa_layer.hex()}')
    print(f'CANDIDATE={flag.decode("ascii")} LENGTH={len(flag)}')
    print('CANDIDATE_BYTES_HEX=', flag.hex())
    if flag != EXPECTED_FLAG:
        raise ValueError(f'independently recovered candidate differs: {flag!r}')

    rc4_forward = rc4_style(flag, RUNTIME_KEY, subtract=False)
    forward_numbers = [pow(byte, RSA_E, RSA_N) for byte in rc4_forward]
    generated = [custom_b64_encode(str(value).encode('ascii')) for value in forward_numbers]
    print('=== 38 END-TO-END TOKEN COMPARISONS ===')
    mismatches = []
    for i, (source, out) in enumerate(zip(targets, generated)):
        passed = source == out
        print(f'ITEM[{i:02d}] expected={source} actual={out} MATCH={passed}')
        if not passed:
            mismatches.append(i)
    all_38 = len(targets) == len(generated) == 38 and not mismatches
    print(f'TOKEN_COUNTS target={len(targets)} generated={len(generated)} all_38_match={all_38}')
    print('CHECK RSA per-item public roundtrip:', all(a == b for a, b in zip(cipher_integers, rsa_roundtrip)))
    print('CHECK recovered flag syntax:', flag.startswith(b'flag{') and flag.endswith(b'}'))
    print('CHECK exact candidate bytes:', flag == EXPECTED_FLAG)
    print('CHECK all 38 end-to-end tokens:', all_38)
    if not all_38:
        raise SystemExit(1)

if __name__ == '__main__':
    main()


