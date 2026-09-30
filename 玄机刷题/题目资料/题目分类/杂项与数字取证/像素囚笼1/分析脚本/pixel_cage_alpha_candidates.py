from pathlib import Path
from zipfile import ZipFile
p = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
candidates = ['acebfdac','ACEBFDAC','abcdefab','ABCDEFAB','cabdfeca','bafedcba','acfebdac','abcde']
with ZipFile(p) as z:
    for password in candidates:
        try:
            data = z.read('secret.txt', pwd=password.encode())
            print('PASSWORD FOUND:', repr(password))
            print('SECRET.TXT:', data.decode(errors='replace'))
            break
        except Exception as exc:
            print('rejected:', password, type(exc).__name__)
    else:
        print('No alphabet-mapped candidate matched.')
