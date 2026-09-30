"""Reproduce the local Ark challenge transform in reverse and verify it forward."""
from __future__ import annotations

import base64
import hashlib
import struct
from pathlib import Path


ABC = Path(r"附件解包\HAP内容\ets\modules.abc")
TARGET_ARRAY_OFFSET = 0x265A  # Index constructor's createarraywithbuffer resolves here.
CUSTOM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
STANDARD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
N, E, D = 75067, 7, 42583
KEYS = (b"OHCTF2025", b"OHCTF2026")


def mutf_string(data: bytes, off: int) -> tuple[str, int]:
    first = data[off]
    length = first >> 1
    raw = data[off + 1:off + 1 + length]
    return raw.decode("utf-8", errors="replace"), off + 1 + length + 1


def rc4_keystream(key: bytes, size: int) -> bytes:
    if not key:
        raise ValueError("empty key")
    s = list(range(256))
    j = 0
    for i in range(256):
        # The challenge indexes both S and key with j, not i, during KSA.
        j = (j + s[j] + key[j % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for _ in range(size):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def rc4_add(key: bytes, data: bytes) -> bytes:
    """Ark challenge variant: output byte = (input byte + RC4 PRGA byte) mod 256."""
    stream = rc4_keystream(key, len(data))
    return bytes((byte + ks) & 0xFF for byte, ks in zip(data, stream))


def rc4_sub(key: bytes, data: bytes) -> bytes:
    """Invert the challenge variant: input byte = (output byte - PRGA byte) mod 256."""
    stream = rc4_keystream(key, len(data))
    return bytes((byte - ks) & 0xFF for byte, ks in zip(data, stream))


def main() -> None:
    blob = ABC.read_bytes()
    print(f"ABC_SHA256={hashlib.sha256(blob).hexdigest().upper()} SIZE={len(blob)}")
    n_literals = struct.unpack_from("<I", blob, TARGET_ARRAY_OFFSET)[0]
    pos = TARGET_ARRAY_OFFSET + 4
    if n_literals % 2:
        raise ValueError(f"unexpected odd LiteralDataAccessor slot count: {n_literals}")
    literal_count = n_literals // 2
    strings = []
    for index in range(literal_count):
        tag = blob[pos]
        pos += 1
        if tag != 5:
            print(f"ARRAY_LITERAL[{index}] NON_STRING_TAG=0x{tag:02x} at=0x{pos-1:x}")
            break
        string_off = struct.unpack_from("<I", blob, pos)[0]
        pos += 4
        text, _ = mutf_string(blob, string_off)
        strings.append(text)
        print(f"TARGET[{len(strings)-1:02}] offset=0x{string_off:x} token={text}")
    print(f"LITERALARRAY_REPORTED_SLOT_COUNT={n_literals} TARGET_LITERAL_COUNT={literal_count} TARGET_STRINGS_DECODED={len(strings)}")

    trans = str.maketrans(CUSTOM, STANDARD)
    cipher_ints = []
    for i, token in enumerate(strings):
        ascii_bytes = base64.b64decode(token.translate(trans), validate=True)
        number = int(ascii_bytes.decode("ascii"))
        cipher_ints.append(number)
        print(f"CUSTOM_B64[{i:02}] {token} -> decimal_ascii={ascii_bytes!r} -> rsa_cipher={number}")

    intermediate = bytes(pow(c, D, N) for c in cipher_ints)
    rsa_roundtrip = all(pow(m, E, N) == c for m, c in zip(intermediate, cipher_ints))
    print(f"RSA_N={N} E={E} D={D}")
    print(f"RSA_PREIMAGE_COUNT={len(intermediate)} ROUNDTRIP_ALL={rsa_roundtrip}")
    print(f"RC4_INPUT_HEX={intermediate.hex()}")
    for key in KEYS:
        plaintext = rc4_sub(key, intermediate)
        check = rc4_add(key, plaintext)
        rsa_forward = [pow(value, E, N) for value in check]
        forward = []
        for value in rsa_forward:
            decimal = str(value).encode("ascii")
            encoded = base64.b64encode(decimal).decode("ascii").translate(str.maketrans(STANDARD, CUSTOM))
            forward.append(encoded)
        print(f"RC4_KEY={key!r}")
        print(f"PLAINTEXT_HEX={plaintext.hex()}")
        print(f"PLAINTEXT_REPR={plaintext!r}")
        print(f"FLAG_SYNTAX={plaintext.startswith(b'flag{') and plaintext.endswith(b'}')}")
        try:
            print(f"PLAINTEXT_UTF8={plaintext.decode('utf-8')}")
        except UnicodeDecodeError as exc:
            print(f"PLAINTEXT_UTF8_ERROR={exc}")
        print(f"RC4_ADD_ROUNDTRIP={check == intermediate}")
        print(f"FULL_FORWARD_MATCH={forward == strings}")
        if forward != strings:
            for i, (a, b) in enumerate(zip(forward, strings)):
                if a != b:
                    print(f"MISMATCH[{i}] computed={a} target={b}")


if __name__ == "__main__":
    main()
