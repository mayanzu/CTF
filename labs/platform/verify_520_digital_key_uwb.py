#!/usr/bin/env python3
"""Independent consistency checks for challenge #520's SQLite evidence.

Usage: python verify_520_digital_key_uwb.py <sqlite-or-platform-zip>
Requires the sibling solve_520_digital_key_uwb.py and OpenSSL with SM4.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import sqlite3
import subprocess
import tempfile
from pathlib import Path
import solve_520_digital_key_uwb as solve

P = int("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
N = solve.P256_N
A = P - 3
G = (
    int("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
    int("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
)
INF = None


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return INF
    if p1 == p2:
        slope = ((3 * x1 * x1 + A) * pow(2 * y1, -1, P)) % P
    else:
        slope = ((y2 - y1) * pow((x2 - x1) % P, -1, P)) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def point_mul(scalar, point):
    result = INF
    while scalar:
        if scalar & 1:
            result = point_add(result, point)
        point = point_add(point, point)
        scalar >>= 1
    return result


def verify_signature(row, public_key):
    z = solve.as_int(row["digest_hex"])
    r = solve.as_int(row["r_hex"])
    s = solve.as_int(row["s_hex"])
    w = pow(s, -1, N)
    candidate = point_add(point_mul((z * w) % N, G), point_mul((r * w) % N, public_key))
    return candidate is not None and candidate[0] % N == r


def openssl_encrypt_pkcs7(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    with tempfile.TemporaryDirectory(prefix="xj520-verify-") as tmp:
        source = Path(tmp) / "plain.bin"
        source.write_bytes(plaintext)
        cmd = ["openssl", "enc", "-sm4-cbc", "-e", "-K", key.hex(), "-iv", iv.hex(), "-in", str(source)]
        result = subprocess.run(cmd, capture_output=True, check=False)
        if result.returncode:
            raise RuntimeError(result.stderr.decode("utf-8", "replace"))
        return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attachment", type=Path)
    source = parser.parse_args().attachment.resolve()
    print(f"source={source}")
    print(f"source_sha256={hashlib.sha256(source.read_bytes()).hexdigest()}")
    with tempfile.TemporaryDirectory(prefix="xj520-verify-db-") as temp:
        db = solve.open_database(source, Path(temp))
        conn = sqlite3.connect(db.as_uri() + "?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            signatures = solve.rows_as_dicts(conn, "auth_signatures")
            metadata = {row["key"]: row["value"] for row in conn.execute("SELECT key,value FROM meta")}
            blob = dict(conn.execute("SELECT * FROM protected_vehicle_blob ORDER BY id LIMIT 1").fetchone())
        finally:
            conn.close()

    for row in signatures:
        digest = hashlib.sha256(row["signed_json"].encode("utf-8")).hexdigest()
        print(f"digest_matches_signed_json[{row['session_id']}]={digest == row['digest_hex'].lower()}")
    first, second = solve.find_reused_pair(signatures)
    k, d, r = solve.recover_k_and_d(first, second)
    pub = (solve.as_int(metadata["public_key_x"]), solve.as_int(metadata["public_key_y"]))
    print(f"sessions={first['session_id']},{second['session_id']}")
    print(f"nonce_tag={first['nonce_tag']} shared_r={solve.as_int(first['r_hex']) == solve.as_int(second['r_hex'])}")
    print(f"recovered_k={k:064x}")
    print(f"recovered_private_key={d:064x}")
    print(f"derived_public_key_matches_meta={point_mul(d, G) == pub}")
    for index, row in enumerate((first, second), start=1):
        print(f"ecdsa_standard_verify[{index}]={verify_signature(row, pub)}")

    key = hashlib.sha256(d.to_bytes(32, "big")).digest()[:16]
    iv = bytes.fromhex(blob["iv_hex"])
    ciphertext = base64.b64decode(blob["ciphertext_b64"], validate=True)
    plaintext = solve.decrypt_sm4_cbc(ciphertext, key, iv)
    rebuilt = openssl_encrypt_pkcs7(plaintext, key, iv)
    decoded = json.loads(plaintext)
    print(f"sm4_key={key.hex()}")
    print(f"ciphertext_length={len(ciphertext)}")
    print(f"plaintext_sha256={hashlib.sha256(plaintext).hexdigest()}")
    print(f"openssl_reencrypt_matches_original={rebuilt == ciphertext}")
    print(f"plaintext_json={json.dumps(decoded, ensure_ascii=False, separators=(',', ':'))}")
    print(f"flag={decoded['flag']}")


if __name__ == "__main__":
    main()
