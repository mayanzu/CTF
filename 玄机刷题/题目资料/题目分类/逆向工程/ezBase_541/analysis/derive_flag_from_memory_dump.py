#!/usr/bin/env python3
"""Re-derive the ezBase #541 candidate from the saved UPX-unpacked image."""

from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DUMP = ROOT / "unpacked_runtime.bin"
RAR = ROOT / "附件_平台原件" / "ezBase_platform_20260929.rar"
SAMPLE = ROOT / "附件_平台原件" / "解压复核_20260929" / "ezBase" / "ezre.exe"
EXPECTED_RAR_SHA256 = "0A7420F1D2D832474AD09EA55825900AF75EBA30DEA46DFB63F9A1AD17F0AF18"
EXPECTED_SAMPLE_SHA256 = "607BD3E8E5D7E715F7A9B819C8D5CC235C8DCC22F06A4AE77D0383E46BBDDACE"
TARGET_OFFSET = 0x3000  # VA 0x140004000 in the dump captured from base+0x1000
ALPHABET_OFFSET = 0x3040  # VA 0x140004040
XOR_KEY = 0x04
EXPECTED_INPUT_LENGTH = 0x24  # confirmed by the main-function strlen branch
STANDARD_B64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def nul_terminated(data: bytes, offset: int, label: str) -> bytes:
    end = data.find(b"\0", offset)
    if end < 0:
        raise ValueError(f"{label} has no NUL terminator")
    return data[offset:end]


def main() -> None:
    rar_sha256 = hashlib.sha256(RAR.read_bytes()).hexdigest().upper()
    sample_sha256 = hashlib.sha256(SAMPLE.read_bytes()).hexdigest().upper()
    image = DUMP.read_bytes()
    target = nul_terminated(image, TARGET_OFFSET, "comparison target")
    custom_alphabet = nul_terminated(image, ALPHABET_OFFSET, "custom Base64 alphabet")

    if len(custom_alphabet) != 64 or len(set(custom_alphabet)) != 64:
        raise ValueError("custom alphabet is not a permutation of 64 distinct bytes")

    # Reverse the encoder's final XOR, then undo its Base64 alphabet substitution.
    pre_xor = bytes(byte ^ XOR_KEY for byte in target)
    if any(byte not in custom_alphabet for byte in pre_xor):
        raise ValueError("XOR-reversed target contains a byte outside the custom alphabet")
    canonical_b64 = bytes(STANDARD_B64[custom_alphabet.index(byte)] for byte in pre_xor)
    candidate = base64.b64decode(canonical_b64, validate=True)

    standard_encoded = base64.b64encode(candidate)
    custom_encoded = bytes(
        byte if byte == ord("=") else custom_alphabet[STANDARD_B64.index(byte)]
        for byte in standard_encoded
    )
    reencoded = bytes(byte if byte == ord("=") else byte ^ XOR_KEY for byte in custom_encoded)

    print(f"platform_rar_sha256={rar_sha256} matches_expected={rar_sha256 == EXPECTED_RAR_SHA256}")
    print(f"extracted_sample_sha256={sample_sha256} matches_expected={sample_sha256 == EXPECTED_SAMPLE_SHA256}")
    print(f"dump_size={len(image)} dump_sha256={hashlib.sha256(image).hexdigest().upper()}")
    print(f"target_va=0x140004000 target_len={len(target)} target={target.decode('ascii')}")
    print(f"alphabet_va=0x140004040 alphabet_len={len(custom_alphabet)} alphabet={custom_alphabet.decode('ascii')}")
    print(f"xor_key=0x{XOR_KEY:02x}")
    print(f"xor_reversed={pre_xor.decode('ascii')}")
    print(f"canonical_base64={canonical_b64.decode('ascii')}")
    print(f"candidate_len={len(candidate)} candidate={candidate.decode('ascii')}")
    print(f"expected_input_len=0x{EXPECTED_INPUT_LENGTH:x} ({EXPECTED_INPUT_LENGTH}) length_matches={len(candidate) == EXPECTED_INPUT_LENGTH}")
    print(f"standard_base64={standard_encoded.decode('ascii')}")
    print(f"custom_base64={custom_encoded.decode('ascii')}")
    print(f"reencoded={reencoded.decode('ascii')}")
    print(f"roundtrip_exact={reencoded == target}")
    print(f"candidate_sha256={hashlib.sha256(candidate).hexdigest().upper()}")
    print(f"valid_flag_shape={bool(re.fullmatch(rb'flag\{[\x20-\x7e]+\}', candidate))}")

    if len(candidate) != EXPECTED_INPUT_LENGTH:
        raise ValueError("decoded candidate length does not satisfy main-function check")
    if rar_sha256 != EXPECTED_RAR_SHA256 or sample_sha256 != EXPECTED_SAMPLE_SHA256:
        raise ValueError("platform archive or extracted sample hash does not match the recorded source")
    if not re.fullmatch(rb"flag\{[\x20-\x7e]+\}", candidate):
        raise ValueError("decoded candidate does not have a closed flag{...} form")
    if reencoded != target:
        raise ValueError("forward transformation did not reproduce the target")


if __name__ == "__main__":
    main()
