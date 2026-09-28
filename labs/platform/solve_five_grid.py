"""Solve the downloaded 2026 Anwang Cup 五格电文 attachment.

Usage: python3 labs/platform/solve_five_grid.py [path/to/attachment.zip]
"""

import json
import re
import sys
from pathlib import Path
from zipfile import ZipFile


DEFAULT_ZIP = Path(__file__).parent / "attachments" / "586-five-grid.zip"
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def decode(wire: str, alphabet: str) -> str:
    symbols = wire.replace(" ", "")
    bits = "".join(f"{alphabet.index(symbol):05b}" for symbol in symbols)
    whole_bytes = len(bits) // 8
    data = bytes(int(bits[i : i + 8], 2) for i in range(0, whole_bytes * 8, 8))
    return data.decode("utf-8")


def main(path: str) -> None:
    with ZipFile(path) as archive:
        record = json.loads(archive.read("attachments/archive.json"))
    alphabet = record["glyph_plate"]
    if len(alphabet) != 32 or len(set(alphabet)) != 32:
        raise ValueError("glyph_plate must contain 32 distinct symbols")
    sample = decode(record["sample_wire"], alphabet)
    if sample != record["sample_plain"]:
        raise ValueError("sample does not match; check the symbol mapping")
    message = decode(record["dispatch_wire"], alphabet)
    print("sample:", sample)
    print("message:", message)
    print("flag:", re.search(r"flag\{[0-9a-f]{32}\}", message).group())


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else str(DEFAULT_ZIP))
