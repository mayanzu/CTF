from __future__ import annotations

import base64
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ABC = ROOT / "附件解包" / "HAP内容" / "ets" / "modules.abc"
ARRAY_INDEX = 17  # Index constructor's targetCipher literal array
N = 75067
E = 7
KEY = "OHCTF2026"  # onPageShow changes the constructor default to this value
STANDARD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
CUSTOM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"


def read_uleb(data: bytes, pos: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7


def read_string(data: bytes, offset: int) -> str:
    encoded_len, pos = read_uleb(data, offset)
    byte_len = encoded_len >> 1
    raw = data[pos : pos + byte_len]
    if data[pos + byte_len] != 0:
        raise ValueError(f"string at {offset:#x} has no NUL terminator")
    return raw.decode("utf-8")


def target_tokens(data: bytes) -> tuple[int, list[str]]:
    count = struct.unpack_from("<I", data, 0x2C)[0]
    index_off = struct.unpack_from("<I", data, 0x30)[0]
    if ARRAY_INDEX >= count:
        raise ValueError(f"literal array index {ARRAY_INDEX} outside count {count}")
    array_off = struct.unpack_from("<I", data, index_off + 4 * ARRAY_INDEX)[0]
    literal_count = struct.unpack_from("<I", data, array_off)[0]
    if literal_count % 2:
        raise ValueError(f"odd literal count: {literal_count}")
    pos = array_off + 4
    tokens = []
    for item in range(literal_count // 2):
        tag = data[pos]
        pos += 1
        value_id = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if tag != 0x05:
            raise ValueError(f"target item {item} has literal tag {tag:#x}, expected STRING")
        tokens.append(read_string(data, value_id))
    return array_off, tokens


def decode_custom_b64(token: str) -> bytes:
    custom_to_standard = str.maketrans(CUSTOM, STANDARD)
    return base64.b64decode(token.translate(custom_to_standard), validate=True)


def encode_custom_b64(raw: bytes) -> str:
    standard_to_custom = str.maketrans(STANDARD, CUSTOM)
    return base64.b64encode(raw).decode("ascii").translate(standard_to_custom)


def rc4_add(data: bytes, key: str, *, reverse: bool) -> bytes:
    key_bytes = key.encode("utf-8")
    if not key_bytes:
        raise ValueError("empty key")
    sbox = list(range(256))
    j = 0
    # The ABC indexes Sbox and key by j in its KSA loop.
    for i in range(256):
        j = (j + sbox[j] + key_bytes[j % len(key_bytes)]) & 0xFF
        sbox[i], sbox[j] = sbox[j], sbox[i]
    i = j = 0
    out = bytearray()
    for value in data:
        i = (i + 1) & 0xFF
        j = (j + sbox[i]) & 0xFF
        sbox[i], sbox[j] = sbox[j], sbox[i]
        stream_byte = sbox[(sbox[i] + sbox[j]) & 0xFF]
        out.append((value - stream_byte) & 0xFF if reverse else (value + stream_byte) & 0xFF)
    return bytes(out)


def main() -> None:
    data = ABC.read_bytes()
    array_off, tokens = target_tokens(data)
    if len(tokens) != 38:
        raise ValueError(f"expected 38 target entries, got {len(tokens)}")
    decimal_cipher = [int(decode_custom_b64(token).decode("ascii")) for token in tokens]
    phi = (271 - 1) * (277 - 1)
    d = pow(E, -1, phi)
    if d != 42583:
        raise ValueError(f"unexpected RSA private exponent: {d}")
    rsa_layer = bytes(pow(c, d, N) for c in decimal_cipher)
    flag_bytes = rc4_add(rsa_layer, KEY, reverse=True)
    flag = flag_bytes.decode("ascii")

    # Forward verification of every layer against the original literal array.
    rc4_layer = rc4_add(flag_bytes, KEY, reverse=False)
    rsa_forward = [pow(value, E, N) for value in rc4_layer]
    tokens_forward = [encode_custom_b64(str(value).encode("ascii")) for value in rsa_forward]
    checks = {
        "RSA public-key roundtrip": rsa_forward == decimal_cipher,
        "custom Base64 token-by-token roundtrip": tokens_forward == tokens,
        "flag syntax": flag.startswith("flag{") and flag.endswith("}"),
        "flag length": len(flag_bytes) == len(tokens),
    }

    print(f"ABC_BYTES={len(data)}")
    print(f"ABC_SHA256={hashlib.sha256(data).hexdigest().upper()}")
    print(f"TARGET_ARRAY_INDEX={ARRAY_INDEX} OFFSET=0x{array_off:x} LITERAL_COUNT=76 TOKEN_COUNT={len(tokens)}")
    print(f"RSA=n:{N},e:{E},p:271,q:277,phi:{phi},d:{d}")
    print(f"KEY={KEY}")
    print(f"TARGET_DECIMAL_CIPHERS={decimal_cipher}")
    print(f"RSA_LAYER_BYTES_HEX={rsa_layer.hex()}")
    print(f"RECOVERED_FLAG={flag}")
    print(f"FORWARD_TOKENS={tokens_forward}")
    for name, passed in checks.items():
        print(f"CHECK {name}: {'PASS' if passed else 'FAIL'}")
    if not all(checks.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
