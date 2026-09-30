from __future__ import annotations
from pathlib import Path
import hashlib
import re

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / 'analysis' / 'extracted'
BIN = DATA_DIR / 'butterfly'
ENC = DATA_DIR / 'encode.dat'
KEYFILE = DATA_DIR / 'encode.dat.key'
RODATA_FILE_OFFSET = 0x825B6
KEY_BYTES = 8
MASK64 = (1 << 64) - 1

def rol64(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & MASK64

def ror64(x: int, n: int) -> int:
    n %= 64
    return ((x >> n) | (x << (64 - n))) & MASK64

def swap_adjacent_pairs(b: bytes) -> bytes:
    assert len(b) == 8
    return bytes(v for i in range(0, 8, 2) for v in (b[i + 1], b[i]))

def encrypt_block(plain: bytes, key: bytes) -> bytes:
    assert len(plain) == len(key) == 8
    x = bytes(a ^ b for a, b in zip(plain, key))
    x = swap_adjacent_pairs(x)
    x = rol64(int.from_bytes(x, 'little'), 1).to_bytes(8, 'little')
    return bytes((a + b) & 0xff for a, b in zip(x, key))

def decrypt_block(cipher: bytes, key: bytes) -> bytes:
    assert len(cipher) == len(key) == 8
    x = bytes((a - b) & 0xff for a, b in zip(cipher, key))
    x = ror64(int.from_bytes(x, 'little'), 1).to_bytes(8, 'little')
    x = swap_adjacent_pairs(x)
    return bytes(a ^ b for a, b in zip(x, key))

def main() -> None:
    binary = BIN.read_bytes()
    cipher = ENC.read_bytes()
    keyfile = KEYFILE.read_bytes()
    rodata_key = binary[RODATA_FILE_OFFSET:RODATA_FILE_OFFSET + 32]
    key = keyfile[:KEY_BYTES]
    print(f'ELF SHA256       = {hashlib.sha256(binary).hexdigest().upper()}')
    print(f'encode.dat size  = {len(cipher)}')
    print(f'encode.dat hex   = {cipher.hex()}')
    print(f'key-file size    = {len(keyfile)}')
    print(f'key-file hex     = {keyfile.hex()}')
    print(f'rodata[0x825b6:] = {rodata_key.hex()}')
    print(f'keyfile == rodata first 32 = {keyfile == rodata_key}')
    print(f'working key (8B)= {key.hex()} ({key!r})')
    out = bytearray(cipher)
    full_len = (len(cipher) // KEY_BYTES) * KEY_BYTES
    for off in range(0, full_len, KEY_BYTES):
        out[off:off + KEY_BYTES] = decrypt_block(cipher[off:off + KEY_BYTES], key)
        print(f'block[{off:02d}] C={cipher[off:off+8].hex()} P={out[off:off+8].hex()}')
    plain = bytes(out)
    print(f'plaintext hex    = {plain.hex()}')
    print(f'plaintext repr   = {plain!r}')
    print(f'plaintext utf8   = {plain.decode("utf-8", errors="replace")}')
    print(f'untouched tail   = {plain[full_len:].hex()} (length {len(plain)-full_len})')
    # Verify the inverse against every transformed byte and verify the remainder is unchanged.
    check = bytearray(plain)
    for off in range(0, full_len, KEY_BYTES):
        check[off:off + KEY_BYTES] = encrypt_block(plain[off:off + KEY_BYTES], key)
    print(f'forward closure  = {bytes(check) == cipher}')
    print(f'forward hex      = {bytes(check).hex()}')
    token = re.findall(rb'flag\{[^}]+\}', plain)
    candidate = token[0] if token else b''
    (ROOT / 'analysis' / 'recovered_plaintext.bin').write_bytes(plain)
    if candidate:
        (ROOT / 'analysis' / 'candidate.txt').write_bytes(candidate + b'\n')
    print(f'candidate flag    = {candidate.decode("ascii", errors="replace")}')
    print(f'candidate length  = {len(candidate)} bytes (trailing data LF excluded)')
    print(f'plaintext final LF= {plain.endswith(bytes([10]))}; final bytes={plain[-4:].hex()}')
    print(f'candidate tokens  = {[m.decode("ascii", errors="replace") for m in re.findall(rb"[A-Za-z0-9_{}-]{6,}", plain)]}')

if __name__ == '__main__':
    main()
