#!/usr/bin/env python3
"""Recover the audit fragments from Xuanji challenge 591's ZIP attachment."""

from __future__ import annotations

import csv
import io
import json
import sys
import zipfile
from pathlib import Path


DEFAULT_ZIP = Path(__file__).parent / "attachments" / "591-poisoned-samples.zip"


def main() -> None:
    archive_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_ZIP
    with zipfile.ZipFile(archive_path) as archive:
        root = "poisoned_samples_bundle/"
        metadata = json.loads(archive.read(root + "metadata.json"))
        rows = list(
            csv.DictReader(
                io.StringIO(archive.read(root + "train_samples.csv").decode("utf-8"))
            )
        )

    trigger = metadata["trigger"]
    target_label = metadata["target_label"]
    selected: dict[int, dict[str, str]] = {}
    for row in rows:
        text = row["text"] or ""
        if trigger not in text or row["label"] != target_label:
            continue
        if not row["poison_order"] or not row["fragment"]:
            continue
        order = int(row["poison_order"])
        fragment = row["fragment"]
        if not 1 <= order <= 4 or len(fragment) != 8:
            continue
        if order in selected:
            raise SystemExit(f"duplicate candidate for poison_order={order}")
        selected[order] = row

    expected_orders = set(range(1, 5))
    if set(selected) != expected_orders:
        raise SystemExit(f"expected poison orders 1..4; found {sorted(selected)}")

    print("order  sample_id  fragment")
    for order, row in sorted(selected.items()):
        print(f"{order:<6} {row['sample_id']:<10} {row['fragment']}")
    flag = "flag{" + "".join(selected[i]["fragment"] for i in range(1, 5)) + "}"
    print(flag)


if __name__ == "__main__":
    main()
