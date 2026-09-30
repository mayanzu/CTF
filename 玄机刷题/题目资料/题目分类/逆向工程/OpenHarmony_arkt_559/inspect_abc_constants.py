import base64
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = path.read_bytes()
print(f'FILE={path.resolve()}')
print(f'SIZE={len(data)}')
print(f'SHA256={__import__("hashlib").sha256(data).hexdigest()}')
standard = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
custom = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/'
values = '''ndG5nZa= nte3ndK= nJy2nJi= mtK0mJG= nde5mZK= nJG4mW== mJu4nti= mJq4ndK= nJG4mW== mJa0mZG= nJaXma== mta5nZa= mta4nta= mZa2ndG= mJy1ntm= mZiYmJC= mJy5ntq= odqXmG== mta1otC= nJyZndq= nZaYotq= ndq0odK= nJG4mW== mZa2ndG= nJaZmq== mtK0nJa= ndy5ndu= mJmZma== nZaZndm= ndy3nZG= nJe4mta= ndaZnde= nZm3ndy= mJmZma== nJyYmJe= mtK0nJa='''.split()
print('--- BASE64 STRING CONSTANTS ---')
for value in values:
    std = base64.b64decode(value)
    trans = str.maketrans(custom, standard)
    custom_dec = base64.b64decode(value.translate(trans))
    print(f'{value}\tstd={std.hex()}:{std!r}\tcustom={custom_dec.hex()}:{custom_dec!r}')
print('--- PRINTABLE ASCII RUNS, MINLEN=4 ---')
for match in re.finditer(rb'[\x20-\x7e]{4,}', data):
    raw = match.group()
    print(f'{match.start():08x}\t{len(raw):4d}\t{raw.decode("ascii")}')
