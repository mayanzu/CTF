"""Solve the downloaded 2026 Anwang Cup 联号回执 attachment.

Usage: python3 labs/platform/solve_receipt.py [path/to/attachment.zip]
"""

import json
import math
import re
import sys
from pathlib import Path
from zipfile import ZipFile


DEFAULT_ZIP = Path(__file__).parent / "attachments" / "587-linked-receipts.zip"
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def bezout(a: int, b: int) -> tuple[int, int, int]:
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def main(path: str) -> None:
    with ZipFile(path) as archive:
        first, second = json.loads(archive.read("attachments/export.json"))["records"]
    n1, n2 = int(first["modulus"]), int(second["modulus"])
    if n1 != n2:
        raise ValueError("the two records have different moduli")
    e1, e2 = int(first["exponent"]), int(second["exponent"])
    c1, c2 = int(first["ciphertext"]), int(second["ciphertext"])
    gcd, a, b = bezout(e1, e2)
    if gcd != 1 or math.gcd(c1, n1) != 1 or math.gcd(c2, n1) != 1:
        raise ValueError("common-modulus conditions are not met")
    message_number = (pow(c1, a, n1) * pow(c2, b, n1)) % n1
    if pow(message_number, e1, n1) != c1 or pow(message_number, e2, n1) != c2:
        raise ValueError("re-encryption check failed")
    data = message_number.to_bytes((message_number.bit_length() + 7) // 8, "big")
    message = data.decode("utf-8")
    print("coefficients:", a, b)
    print("message:", message)
    print("flag:", re.search(r"flag\{[0-9a-f]{32}\}", message).group())


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else str(DEFAULT_ZIP))
