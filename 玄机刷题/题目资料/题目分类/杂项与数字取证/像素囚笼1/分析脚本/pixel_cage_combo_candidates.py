from pathlib import Path
from zipfile import ZipFile
p = Path(str(Path(__file__).resolve().parents[1] / '附件' / 'challenge.png'))
candidates = ['02413502','ACEBDFAC','acebdfac','20531420','cafedeca','B40R46Y52G58P64C70B76R82','B40R46Y52G58P64C70B76R82'.lower(),'B40-46-52-58-64-70-76-82']
with ZipFile(p) as z:
    for password in candidates:
        try:
            data = z.read('secret.txt', pwd=password.encode())
            print('PASSWORD FOUND:', repr(password))
            print('SECRET.TXT:', data.decode(errors='replace'))
            break
        except Exception as exc:
            print('rejected:', repr(password), type(exc).__name__)
    else:
        print('No zero-based / shape-combination candidate matched.')
