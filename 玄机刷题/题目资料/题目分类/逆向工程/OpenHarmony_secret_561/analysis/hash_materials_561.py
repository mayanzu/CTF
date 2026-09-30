#!/usr/bin/env python3
"""Write a reproducible SHA-256 manifest for #561's source materials."""
from __future__ import annotations

import csv
import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "analysis" / "sha256_manifest_20260929.csv"
SOURCE_FILES = (
    ("secret_platform_20260929.zip", ROOT / "secret_platform_20260929.zip"),
    ("secret.hap", ROOT / "secret.hap"),
    ("附件_20260929/secret.hap", ROOT / "附件_20260929" / "secret.hap"),
)


def main() -> None:
    files = list(SOURCE_FILES)
    extracted = ROOT / "hap_contents"
    files.extend(
        (path.relative_to(ROOT).as_posix(), path)
        for path in sorted(extracted.rglob("*"))
        if path.is_file()
    )
    rows: list[tuple[str, int, str]] = []
    for relative, path in files:
        data = path.read_bytes()
        rows.append((relative, len(data), hashlib.sha256(data).hexdigest().upper()))

    with OUTPUT.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(("relative_path", "size_bytes", "sha256"))
        writer.writerows(rows)

    print(f"MANIFEST={OUTPUT.relative_to(ROOT).as_posix()}")
    print(f"FILES_HASHED={len(rows)}")
    for relative, size, digest in rows:
        print(f"{digest}  {size:>10}  {relative}")


if __name__ == "__main__":
    main()
