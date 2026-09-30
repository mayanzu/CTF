from pathlib import Path
p=Path(r'Z:\solve_537_from_static.py')
s=p.read_text(encoding='utf-8')
old=r"alphabet=b[alphabet_off:b.index(b'\0',alphabet_off)]"
new="alphabet=b[alphabet_off:alphabet_off+64]\nassert b[alphabet_off+64:alphabet_off+72] == b'Find me!', b[alphabet_off+64:alphabet_off+72]"
assert old in s, 'old alphabet extraction line not found'
p.write_text(s.replace(old,new),encoding='utf-8')
print('updated alphabet extraction to exactly 64 bytes and asserted adjacent prompt')
