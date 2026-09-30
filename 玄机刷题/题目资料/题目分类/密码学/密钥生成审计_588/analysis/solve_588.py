#!/usr/bin/env python3
"""Clone CPython's MT19937 state from 624 published outputs; never run the challenge source."""
from __future__ import annotations
import json
from pathlib import Path
import random

MASK32 = 0xFFFFFFFF
N = 624


def undo_right(y: int, shift: int) -> int:
    x = y
    for _ in range((32 + shift - 1) // shift):
        x = y ^ (x >> shift)
    return x & MASK32


def undo_left_mask(y: int, shift: int, mask: int) -> int:
    x = y
    for _ in range((32 + shift - 1) // shift):
        x = y ^ ((x << shift) & mask)
    return x & MASK32


def untemper(y: int) -> int:
    y = undo_right(y, 18)
    y = undo_left_mask(y, 15, 0xEFC60000)
    y = undo_left_mask(y, 7, 0x9D2C5680)
    y = undo_right(y, 11)
    return y & MASK32


def clone_next(observed: list[int], count: int) -> list[int]:
    if len(observed) != N:
        raise ValueError(f"need exactly {N} outputs, got {len(observed)}")
    state_words = [untemper(x) for x in observed]
    clone = random.Random()
    # random.Random's public state is version 3; 624 is the index immediately
    # after consuming a complete output block, so the next call twists once.
    clone.setstate((3, tuple(state_words + [N]), None))
    return [clone.getrandbits(32) for _ in range(count)]


def main() -> None:
    base = Path(__file__).resolve().parent.parent
    input_path = base / "originals" / "extracted" / "attachments" / "output.txt"
    output_path = Path(__file__).resolve().parent / "derived_material.json"
    lines = [line.strip() for line in input_path.read_text(encoding="ascii").splitlines() if line.strip()]
    if len(lines) != 625:
        raise ValueError(f"expected 624 decimal outputs + 1 ciphertext line; found {len(lines)} lines")
    observed = [int(x, 10) for x in lines[:624]]
    if any(not (0 <= x <= MASK32) for x in observed):
        raise ValueError("a public output is outside uint32 range")
    ciphertext = bytes.fromhex(lines[624])
    if len(ciphertext) == 0 or len(ciphertext) % 16:
        raise ValueError(f"AES-ECB ciphertext length must be a positive multiple of 16; got {len(ciphertext)}")
    if any((temper(untemper(value)) & MASK32) != value for value in observed):
        raise AssertionError("untemper round-trip failed")

    # Self-test the cloning logic against an independent deterministic stream.
    reference = random.Random(0x5882026)
    reference_outputs = [reference.getrandbits(32) for _ in range(N + 4)]
    selftest_prediction = clone_next(reference_outputs[:N], 4)
    if selftest_prediction != reference_outputs[N:]:
        raise AssertionError("MT19937 clone self-test failed")

    next_words = clone_next(observed, 4)
    key = b"".join(word.to_bytes(4, "big") for word in next_words)
    material = {
        "source": str(input_path),
        "observed_output_count": len(observed),
        "first_public_output": observed[0],
        "last_public_output": observed[-1],
        "next_four_outputs": next_words,
        "aes_key_hex": key.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "ciphertext_bytes": len(ciphertext),
        "self_test": "PASS: predicted outputs 625-628 match a fresh deterministic CPython MT19937 stream",
    }
    output_path.write_text(json.dumps(material, indent=2) + "\n", encoding="utf-8")
    print("INPUT=originals/extracted/attachments/output.txt")
    print(f"PUBLIC_OUTPUTS={len(observed)}")
    print(f"PUBLIC_FIRST={observed[0]}")
    print(f"PUBLIC_LAST={observed[-1]}")
    print("UNTEMPER_ROUNDTRIP=PASS (624/624)")
    print(f"CLONE_SELFTEST={material['self_test']}")
    print("PREDICTED_OUTPUTS=" + ",".join(str(x) for x in next_words))
    print(f"AES128_KEY={key.hex()}")
    print(f"CIPHERTEXT_BYTES={len(ciphertext)}")
    print("DERIVED_MATERIAL=analysis/derived_material.json")


def temper(y: int) -> int:
    y ^= y >> 11
    y ^= (y << 7) & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    y ^= y >> 18
    return y & MASK32


if __name__ == "__main__":
    main()