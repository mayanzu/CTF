"""Static, offline reproduction of Xuanji challenge #559.

Uses only Python's standard library. It reads the supplied ZIP/HAP/ABC files;
it never launches the challenge application or any executable from the archive.
"""
from __future__ import annotations

import base64
import hashlib
import math
import struct
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ZIP_PATH = ROOT / "附件" / "arkt_platform_20260929.zip"
HAP_PATH = ROOT / "附件解包" / "task_5.hap"
ABC_PATH = ROOT / "附件解包" / "HAP内容" / "ets" / "modules.abc"
EXPECTED_HASHES = {
    "platform ZIP": "81D7F3225DC36345A968A2F498E00AAD570C08B8DCAD89E13405BD3195A4263B",
    "HAP": "AFF302A750AF02C649ECCC1FB504F348B74F76366B708389CE38971A0B58F3DA",
    "Ark ABC": "AA0579A16AF1D76438040F1470C46A007B5C7AE386AFF775C09EB82C0BE6F03F",
}

ARRAY_INDEX = 17
ARRAY_OFFSET_FROM_CODE = 0x265A
SLOT_COUNT = 76
RSA_P, RSA_Q, RSA_E = 271, 277, 7
RSA_N = RSA_P * RSA_Q
RUNTIME_KEY = b"OHCTF2026"
STANDARD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
CUSTOM_B64 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def read_uleb(data: bytes, offset: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        if offset >= len(data):
            raise ValueError("truncated ABC variable-length integer")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7
        if shift > 63:
            raise ValueError("ABC variable-length integer overflow")


def read_abc_string(data: bytes, offset: int) -> str:
    tagged_length, start = read_uleb(data, offset)
    length = tagged_length >> 1
    end = start + length
    if end >= len(data) or data[end] != 0:
        raise ValueError(f"invalid ABC string at 0x{offset:x}")
    return data[start:end].decode("ascii")


def read_targets(data: bytes) -> tuple[int, list[str]]:
    if len(data) < 0x34:
        raise ValueError("ABC header too short")
    array_count = struct.unpack_from("<I", data, 0x2C)[0]
    index_offset = struct.unpack_from("<I", data, 0x30)[0]
    if not array_count or index_offset >= len(data) or ARRAY_INDEX >= array_count:
        raise ValueError("invalid ABC LiteralArray index table")
    array_offset = struct.unpack_from("<I", data, index_offset + ARRAY_INDEX * 4)[0]
    if array_offset != ARRAY_OFFSET_FROM_CODE:
        raise ValueError(
            f"LiteralArray index {ARRAY_INDEX} resolved to 0x{array_offset:x}, "
            f"expected 0x{ARRAY_OFFSET_FROM_CODE:x} from constructor reference"
        )
    slots = struct.unpack_from("<I", data, array_offset)[0]
    if slots != SLOT_COUNT or slots % 2:
        raise ValueError(f"unexpected LiteralArray slot count: {slots}")
    cursor = array_offset + 4
    targets = []
    for index in range(slots // 2):
        tag = data[cursor]
        cursor += 1
        value_offset = struct.unpack_from("<I", data, cursor)[0]
        cursor += 4
        if tag != 0x05:
            raise ValueError(f"target[{index}] has non-string tag 0x{tag:02x}")
        targets.append(read_abc_string(data, value_offset))
    return array_offset, targets


def custom_b64_decode(token: str) -> bytes:
    inverse = {custom: standard for standard, custom in zip(STANDARD_B64, CUSTOM_B64)}
    try:
        standard_token = "".join("=" if c == "=" else inverse[c] for c in token)
    except KeyError as error:
        raise ValueError(f"invalid custom Base64 character: {error.args[0]!r}") from error
    return base64.b64decode(standard_token.encode("ascii"), validate=True)


def custom_b64_encode(payload: bytes) -> str:
    forward = {standard: custom for standard, custom in zip(STANDARD_B64, CUSTOM_B64)}
    encoded = base64.b64encode(payload).decode("ascii")
    return "".join("=" if c == "=" else forward[c] for c in encoded)


def rc4_variant(payload: bytes, key: bytes, *, decrypt: bool) -> bytes:
    """Recover the Ark routine: unusual j-indexed KSA and +/- PRGA stream."""
    if not key:
        raise ValueError("empty key")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[j] + key[j % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    i = j = 0
    result = bytearray()
    for value in payload:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        stream = state[(state[i] + state[j]) & 0xFF]
        result.append((value - stream if decrypt else value + stream) & 0xFF)
    return bytes(result)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    for label, path in (("platform ZIP", ZIP_PATH), ("HAP", HAP_PATH), ("Ark ABC", ABC_PATH)):
        actual = sha256(path.read_bytes())
        print(f"{label} SHA256={actual} SIZE={path.stat().st_size}")
        require(actual == EXPECTED_HASHES[label], f"{label} hash differs from recorded source")

    with zipfile.ZipFile(ZIP_PATH) as archive:
        matches = [entry for entry in archive.namelist() if Path(entry).name.lower() == "task_5.hap"]
        require(len(matches) == 1, f"expected one task_5.hap in platform ZIP, found {len(matches)}")
        archived_hap = archive.read(matches[0])
    extracted_hap = HAP_PATH.read_bytes()
    print(f"ZIP_ENTRY={matches[0]!r} ZIP_HAP_EQUALS_EXTRACTED={archived_hap == extracted_hap}")
    require(archived_hap == extracted_hap, "saved HAP differs from the original ZIP entry")

    with zipfile.ZipFile(HAP_PATH) as hap_archive:
        abc_entries = [entry for entry in hap_archive.namelist() if entry.replace("\\", "/").endswith("ets/modules.abc")]
        require(len(abc_entries) == 1, f"expected one ets/modules.abc in HAP, found {len(abc_entries)}")
        archived_abc = hap_archive.read(abc_entries[0])
    abc = ABC_PATH.read_bytes()
    print(f"HAP_ENTRY={abc_entries[0]!r} HAP_ABC_EQUALS_EXTRACTED={archived_abc == abc}")
    require(archived_abc == abc, "saved modules.abc differs from the HAP entry")

    array_offset, targets = read_targets(abc)
    print(
        f"ABC_MAGIC={abc[:8].hex()} LITERAL_ARRAY_COUNT={struct.unpack_from('<I', abc, 0x2C)[0]} "
        f"INDEX_TABLE_OFFSET=0x{struct.unpack_from('<I', abc, 0x30)[0]:x} "
        f"TARGET_ARRAY_INDEX={ARRAY_INDEX} TARGET_ARRAY_OFFSET=0x{array_offset:x} "
        f"SLOTS={SLOT_COUNT} TARGET_STRINGS={len(targets)}"
    )
    require(len(targets) == SLOT_COUNT // 2 == 38, "wrong target array length")

    ciphertexts = []
    for index, token in enumerate(targets):
        decoded = custom_b64_decode(token)
        decimal = decoded.decode("ascii")
        require(decimal.isdecimal() and str(int(decimal)) == decimal, f"target[{index}] is not canonical decimal")
        ciphertexts.append(int(decimal))
        print(f"TARGET[{index:02}]={token} -> decimal={decimal}")

    phi = (RSA_P - 1) * (RSA_Q - 1)
    private_d = pow(RSA_E, -1, phi)
    require(RSA_N == 75067 and phi == 74520 and private_d == 42583, "RSA parameter check failed")
    rsa_layer = bytes(pow(cipher, private_d, RSA_N) for cipher in ciphertexts)
    require(all(pow(value, RSA_E, RSA_N) == cipher for value, cipher in zip(rsa_layer, ciphertexts)),
            "RSA public round-trip failed")
    print(f"RSA_FACTORS={RSA_P}*{RSA_Q}={RSA_N} PHI={phi} E={RSA_E} D={private_d}")
    print(f"RSA_PREIMAGE_COUNT={len(rsa_layer)} RSA_PREIMAGE_HEX={rsa_layer.hex()}")

    candidate = rc4_variant(rsa_layer, RUNTIME_KEY, decrypt=True)
    print(f"RUNTIME_KEY={RUNTIME_KEY.decode('ascii')} CANDIDATE={candidate.decode('ascii')} LENGTH={len(candidate)}")
    require(candidate.startswith(b"flag{") and candidate.endswith(b"}"), "candidate flag delimiters failed")
    require(len(candidate) == len(targets) == 38, "candidate length does not match target length")

    encrypted_bytes = rc4_variant(candidate, RUNTIME_KEY, decrypt=False)
    generated = [custom_b64_encode(str(pow(value, RSA_E, RSA_N)).encode("ascii")) for value in encrypted_bytes]
    mismatches = []
    for index, (expected, actual) in enumerate(zip(targets, generated)):
        matched = expected == actual
        print(f"FORWARD[{index:02}] expected={expected} actual={actual} MATCH={matched}")
        if not matched:
            mismatches.append(index)
    all_match = len(generated) == len(targets) and not mismatches
    print(f"TOKEN_COUNTS expected={len(targets)} generated={len(generated)} ALL_38_MATCH={all_match}")
    print(f"CHECK RSA_ROUNDTRIP={True} FLAG_SYNTAX={candidate.startswith(b'flag{') and candidate.endswith(b'}')} "
          f"FLAG_LENGTH={len(candidate)} ALL_TOKENS={all_match}")
    require(all_match, f"forward transform mismatches at indexes {mismatches}")


if __name__ == "__main__":
    main()
