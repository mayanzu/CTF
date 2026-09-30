from itertools import product
from pathlib import Path
from time import perf_counter
from zipfile import ZipFile, _ZipDecrypter

archive = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
with ZipFile(archive) as zf:
    info = zf.getinfo('secret.txt')
    raw = archive.read_bytes()
    name_len = int.from_bytes(raw[info.header_offset + 26:info.header_offset + 28], 'little')
    extra_len = int.from_bytes(raw[info.header_offset + 28:info.header_offset + 30], 'little')
    data_at = info.header_offset + 30 + name_len + extra_len
    encrypted_header = raw[data_at:data_at + 12]
    check = (info.CRC >> 24) & 0xff
    print('Enumerating passwords over color digits 1..6, lengths 1..8')
    print('Encrypted header offset:', data_at, 'header check byte:', hex(check))
    started = perf_counter()
    attempts = 0
    for length in range(1, 9):
        for chars in product('123456', repeat=length):
            password = ''.join(chars)
            attempts += 1
            header = _ZipDecrypter(password.encode())(encrypted_header)
            if header[-1] == check:
                try:
                    plain = zf.read(info, pwd=password.encode())
                except Exception:
                    continue
                print('MATCH:', password)
                print('SECRET.TXT:', plain.decode(errors='replace'))
                raise SystemExit
    print('No match after', attempts, 'candidates; seconds=', round(perf_counter() - started, 2))

