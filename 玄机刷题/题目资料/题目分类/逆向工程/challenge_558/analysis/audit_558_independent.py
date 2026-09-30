#!/usr/bin/env python3
"""Independent, offline recalculation for challenge #558.

This deliberately does not import solve_558.py or third_route_verify_20260929.py.
It reads only the supplied archive/extracted PE for hash and ZIP metadata checks;
R.exe is never loaded as executable code.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from zipfile import ZipFile

BASE = Path(__file__).resolve().parent.parent
ZIP_PATH = BASE / "R.zip"
EXE_PATH = BASE / "attachment" / "R.exe"
EXPECTED_ZIP_SHA256 = "CD7967ECD4DA09A57F544E14C28CEAF016272D8B7EC095B949D141D096C408DB"
EXPECTED_EXE_SHA256 = "E2B0CA7ED72159F82649C33F373E3B38C0E9C9283AA1DAEC627018A328F08651"

RAW_KEY = bytes.fromhex("6c 6e 74 66 76 70 75 73")
TARGET = bytes.fromhex("18 59 07 28 f4 ad c8 c3 b6 3f 2d 39 ca 34 d1 8e f5 03 b0")
EXPECTED = b"flag{8a1c2a73c29b2}"

def digest(path: Path) -> str:
    h = sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(part)
    return h.hexdigest().upper()

def make_key(raw: bytes) -> bytes:
    return bytes(value ^ index for index, value in enumerate(raw))

def initialize(key: bytes) -> tuple[list[int], list[tuple[int, ...]]]:
    state = list(range(256))
    j = 0
    first_rounds = []
    for i in range(256):
        key_byte = key[i % len(key)] ^ 0x66
        before_i = state[i]
        j = (j + before_i + key_byte) & 0xff
        before_j = state[j]
        state[i], state[j] = state[j], state[i]
        if i < 8:
            first_rounds.append((i, key_byte, before_i, j, before_j, state[i], state[j]))
    return state, first_rounds

def keystream_masks(state: list[int], length: int) -> tuple[list[int], list[tuple[int, ...]]]:
    i = 0
    j = 0
    masks = []
    rows = []
    for pos in range(length):
        i = (i + 1) & 0xff
        si_before = state[i]
        j = (j + si_before) & 0xff
        state[i], state[j] = state[j], state[i]
        lookup = (state[i] + state[j]) & 0xff
        byte = state[lookup]
        swapped = ((byte << 4) | (byte >> 4)) & 0xff
        mask = (swapped + 1) & 0xff
        masks.append(mask)
        rows.append((pos, i, j, si_before, state[i], state[j], lookup, byte, swapped, mask))
    return masks, rows

def decrypt_target(target: bytes, key: bytes) -> tuple[bytes, list[int], list[tuple[int, ...]]]:
    masks, rows = keystream_masks(initialize(key)[0], len(target))
    plain = bytes((((cipher - 1) & 0xff) ^ mask) for cipher, mask in zip(target, masks))
    return plain, masks, rows

def encrypt_candidate(plain: bytes, key: bytes) -> tuple[bytes, list[int], list[tuple[int, ...]]]:
    masks, rows = keystream_masks(initialize(key)[0], len(plain))
    cipher = bytes((((value ^ mask) + 1) & 0xff) for value, mask in zip(plain, masks))
    return cipher, masks, rows

def main() -> None:
    zip_hash = digest(ZIP_PATH)
    exe_hash = digest(EXE_PATH)
    with ZipFile(ZIP_PATH, "r") as archive:
        entries = [(entry.filename, entry.file_size, entry.compress_size) for entry in archive.infolist()]
    print(f"R_ZIP_SHA256={zip_hash}")
    print(f"R_EXE_SHA256={exe_hash}")
    print(f"ZIP_ENTRIES={entries!r}")
    print(f"ZIP_HASH_MATCH={zip_hash == EXPECTED_ZIP_SHA256}")
    print(f"EXE_HASH_MATCH={exe_hash == EXPECTED_EXE_SHA256}")
    key = make_key(RAW_KEY)
    print(f"RAW_KEY={RAW_KEY.hex()} ({RAW_KEY.decode('ascii')})")
    print(f"EFFECTIVE_KEY={key.hex()} ({key.decode('ascii')})")
    state0, ksa_rows = initialize(key)
    print(f"KSA_STATE_LEN={len(state0)}")
    print("KSA_FIRST8=(round,key_byte_xor_66,S_i_before,j,S_j_before,S_i_after,S_j_after)")
    for row in ksa_rows:
        print(f"KSA={row}")
    print(f"TARGET_LEN={len(TARGET)}")
    print(f"TARGET_HEX={TARGET.hex()}")
    recovered, dec_masks, dec_rows = decrypt_target(TARGET, key)
    print("PRGA_COLUMNS=(pos,i,j,S_i_before,S_i_after,S_j_after,lookup,S_lookup,nibble_swap,mask)")
    for row in dec_rows:
        print(f"PRGA={row}")
    print(f"RECOVERED_HEX={recovered.hex()}")
    print(f"RECOVERED_ASCII={recovered.decode('ascii')}")
    print(f"CANDIDATE_MATCHES_EXPECTED={recovered == EXPECTED}")
    regenerated, enc_masks, _ = encrypt_candidate(recovered, key)
    print(f"FORWARD_CIPHERTEXT={regenerated.hex()}")
    print(f"FORWARD_MATCHES_TARGET={regenerated == TARGET}")
    print(f"ALL_MASKS_MATCH={dec_masks == enc_masks}")
    assert zip_hash == EXPECTED_ZIP_SHA256
    assert exe_hash == EXPECTED_EXE_SHA256
    assert len(entries) == 1 and entries[0][0] == "R.exe" and entries[0][1] == 186880
    assert key == b"loverust"
    assert len(TARGET) == len(EXPECTED) == 19
    assert recovered == EXPECTED
    assert regenerated == TARGET
    assert dec_masks == enc_masks

if __name__ == "__main__":
    main()

