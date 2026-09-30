from pathlib import Path
from zipfile import ZipFile
p = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
with ZipFile(p) as z:
    for password in ['(.4:@FLR', 'RLF@4.:(', '4046525864707682', '40-46-52-58-64-70-76-82']:
        try:
            data = z.read('secret.txt', pwd=password.encode())
            print('PASSWORD FOUND:', repr(password))
            print('SECRET.TXT:', data.decode(errors='replace'))
            break
        except Exception as exc:
            print('rejected:', repr(password), type(exc).__name__)
    else:
        print('No size-derived candidate matched.')
