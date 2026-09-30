#!/usr/bin/env python3
"""Recover the Digital Key UWB flag from its SQLite attachment.

Usage:
    python solve_520_digital_key_uwb.py digital_key_trace.sqlite.zip
    python solve_520_digital_key_uwb.py digital_key_trace.sqlite

Only Python's standard library and an OpenSSL 3 build with SM4 support are used.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import itertools
import json
import sqlite3
import subprocess
import tempfile
import zipfile
from pathlib import Path

P256_N = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)


def as_int(value: object) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    return int(text[2:] if text.startswith("0x") else text, 16)


def open_database(source: Path, temp_dir: Path) -> Path:
    if zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as archive:
            names = [
                name for name in archive.namelist()
                if name.lower().endswith((".sqlite", ".sqlite3", ".db"))
            ]
            if not names:
                raise ValueError("ZIP 内未找到 SQLite 数据库")
            preferred = next(
                (name for name in names if "digital_key_trace" in name.lower()),
                names[0],
            )
            target = temp_dir / Path(preferred).name
            target.write_bytes(archive.read(preferred))
            print(f"[+] database_entry={preferred}")
            return target
    if not source.is_file():
        raise FileNotFoundError(source)
    return source


def rows_as_dicts(conn: sqlite3.Connection, table: str) -> list[dict]:
    cur = conn.execute(f'SELECT * FROM "{table}"')
    names = [item[0] for item in cur.description]
    return [dict(zip(names, row)) for row in cur.fetchall()]


def is_success(row: dict) -> bool:
    for key in ("success", "successful", "ok"):
        if key in row:
            value = row[key]
            if isinstance(value, str):
                return value.strip().lower() in {"1", "true", "yes", "success", "ok"}
            return bool(value)
    for key in ("status", "result", "outcome"):
        if key in row and isinstance(row[key], str):
            value = row[key].strip().lower()
            if value in {"fail", "failed", "failure", "error", "denied"}:
                return False
            if value in {"success", "succeeded", "ok", "valid"}:
                return True
    return True


def find_reused_pair(rows: list[dict]) -> tuple[dict, dict]:
    eligible = [r for r in rows if is_success(r)]
    for left, right in itertools.combinations(eligible, 2):
        if as_int(left["r_hex"]) != as_int(right["r_hex"]):
            continue
        tag1, tag2 = left.get("nonce_tag"), right.get("nonce_tag")
        if tag1 and tag2 and tag1 != tag2:
            continue
        if as_int(left["digest_hex"]) == as_int(right["digest_hex"]):
            continue
        return left, right
    raise ValueError("未找到成功且 digest 不同、r 相同的签名对")


def recover_k_and_d(first: dict, second: dict) -> tuple[int, int, int]:
    r1, r2 = as_int(first["r_hex"]), as_int(second["r_hex"])
    if r1 != r2:
        raise ValueError("签名 r 不同，不能按随机数复用公式恢复")
    s1, s2 = as_int(first["s_hex"]), as_int(second["s_hex"])
    z1, z2 = as_int(first["digest_hex"]), as_int(second["digest_hex"])
    k = ((z1 - z2) * pow((s1 - s2) % P256_N, -1, P256_N)) % P256_N
    d = (((s1 * k - z1) % P256_N) * pow(r1, -1, P256_N)) % P256_N
    for index, (z, s) in enumerate(((z1, s1), (z2, s2)), start=1):
        if (s * k - z - r1 * d) % P256_N != 0:
            raise ValueError(f"ECDSA 第 {index} 条签名方程复核失败")
    return k, d, r1


def decrypt_sm4_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(iv) != 16 or len(ciphertext) == 0 or len(ciphertext) % 16:
        raise ValueError("IV/密文长度不符合 SM4-CBC 分组要求")
    with tempfile.TemporaryDirectory(prefix="xj520-sm4-") as temp:
        input_path = Path(temp) / "cipher.bin"
        input_path.write_bytes(ciphertext)
        command = [
            "openssl", "enc", "-sm4-cbc", "-d", "-nopad",
            "-K", key.hex(), "-iv", iv.hex(), "-in", str(input_path),
        ]
        result = subprocess.run(command, capture_output=True, check=False)
        if result.returncode != 0:
            raise RuntimeError(
                "OpenSSL SM4 解密失败: " + result.stderr.decode("utf-8", "replace")
            )
        padded = result.stdout
    pad = padded[-1]
    if not 1 <= pad <= 16 or padded[-pad:] != bytes([pad]) * pad:
        raise ValueError("SM4 明文的 PKCS#7 填充无效")
    return padded[:-pad]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attachment", type=Path, help="SQLite 数据库或平台下载的 ZIP")
    args = parser.parse_args()
    source = args.attachment.expanduser().resolve()
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    print(f"[+] source={source}")
    print(f"[+] source_sha256={digest}")

    with tempfile.TemporaryDirectory(prefix="xj520-db-") as temp:
        database = open_database(source, Path(temp))
        conn = sqlite3.connect(str(database))
        conn.row_factory = sqlite3.Row
        try:
            tables = {
                row[0] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if not {"auth_signatures", "protected_vehicle_blob"} <= tables:
                raise ValueError(f"数据库表与题目预期不符: {sorted(tables)}")
            signatures = rows_as_dicts(conn, "auth_signatures")
            blobs = rows_as_dicts(conn, "protected_vehicle_blob")
        finally:
            conn.close()

    print(f"[+] auth_signature_rows={len(signatures)}")
    left, right = find_reused_pair(signatures)
    k, d, r = recover_k_and_d(left, right)
    print(f"[+] pair_session_ids={left.get('session_id')},{right.get('session_id')}")
    print(f"[+] nonce_tag={left.get('nonce_tag')}")
    print(f"[+] shared_r={r:064x}")
    print(f"[+] reused_k={k:064x}")
    print(f"[+] private_key_d={d:064x}")
    print("[+] ecdsa_equations=both valid")

    key = hashlib.sha256(d.to_bytes(32, "big")).digest()[:16]
    print(f"[+] sm4_key_sha256_prefix={key.hex()}")
    if not blobs:
        raise ValueError("protected_vehicle_blob 表为空")
    blob = blobs[0]
    alg = str(blob.get("alg", ""))
    if "sm4" not in alg.lower() or "cbc" not in alg.lower():
        raise ValueError(f"不支持的加密算法标记: {alg!r}")
    iv = bytes.fromhex(str(blob["iv_hex"]))
    ciphertext = base64.b64decode(blob["ciphertext_b64"], validate=True)
    print(f"[+] cipher_alg={alg}")
    print(f"[+] iv={iv.hex()}")
    print(f"[+] ciphertext_length={len(ciphertext)}")
    plaintext = decrypt_sm4_cbc(ciphertext, key, iv)
    decoded = json.loads(plaintext)
    print(f"[+] plaintext_json={json.dumps(decoded, ensure_ascii=False, separators=(',', ':'))}")
    flag = decoded.get("flag")
    if not isinstance(flag, str) or not flag.startswith("flag{") or not flag.endswith("}"):
        raise ValueError("解密 JSON 中未找到符合格式的 flag")
    print(f"[+] flag={flag}")


if __name__ == "__main__":
    main()
