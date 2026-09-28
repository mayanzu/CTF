"""Reproduce the verified qgd solution from the official challenge ZIP.

Usage: python3 labs/platform/solve_qgd.py [path/to/qgd.zip]
The executable is inspected as data and is never launched.
"""

import ast
import hashlib
import sys
from pathlib import Path
import zipfile


PART1_SHA256 = "419c75320ad497749d1e3c8f6d2e021372810af53c78902f73c0d8df54363770"
PART2_SHA256 = "1ff70b6314d545f1e71786024c8510a11c6e3e0501bbf78038a8b8b6a2e5194b"

# These two constants come from static inspection of the PyInstaller entry module.
# The challenge gives the 19-byte ciphertext as a Python bytes literal; its longer
# hex string is the key. Do not swap the two despite the misleading variable names.
KEY_HEX = (
    "EC3700DFCD4F364EC54B19C5E7E26DEF6A25087C4FCDF4F8507A40A9019E3B48"
    "BD70129D0141A5B8F089F280F4BE6CCD"
)
CIPHERTEXT_HEX = "907077722132B36010A60684456C77E9A1B540"
DEFAULT_ZIP = Path(__file__).parent / "attachments" / "557-qgd.zip"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def recover_part1(text):
    assert b"83 F0 31" in text and b"83 F0 58" in text
    encrypted = ast.literal_eval(text.split(b"encrypted part1 flag:", 1)[1].strip().decode())
    return bytes(value ^ (0x31 if index % 2 == 0 else 0x58)
                 for index, value in enumerate(encrypted)).decode("ascii")


def recover_part2():
    key = bytes.fromhex(KEY_HEX)
    ciphertext = bytes.fromhex(CIPHERTEXT_HEX)
    state = list(range(128))
    j = 0
    for i in range(128):
        j = ((j + state[i] + key[i % len(key)]) % 128) ^ 55
        state[i], state[j] = state[j], state[i]
    i = j = 0
    plain = bytearray()
    for value in ciphertext:
        i = (i + 1) % 128
        j = (j + state[i]) % 128
        state[i], state[j] = state[j], state[i]
        t = state[(state[i] + state[j]) % 128]
        stream_byte = ((t << 4) | (t >> 4)) & 255
        plain.append(value ^ stream_byte)
    return plain.decode("ascii")


def main(path):
    with zipfile.ZipFile(path) as archive:
        part1_data = archive.read("part1flag.txt")
        part2_binary = archive.read("part2flag.exe")
    if sha256(part1_data) != PART1_SHA256 or sha256(part2_binary) != PART2_SHA256:
        raise SystemExit("Unexpected attachment version; re-check the constants.")
    part1 = recover_part1(part1_data)
    part2 = recover_part2()
    print("part1:", part1)
    print("part2:", part2)
    print("flag:", f"flag{{{part1}/{part2}}}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else str(DEFAULT_ZIP))
