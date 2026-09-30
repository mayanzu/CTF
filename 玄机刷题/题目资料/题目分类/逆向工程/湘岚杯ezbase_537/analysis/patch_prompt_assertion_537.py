from pathlib import Path
p=Path(r'Z:\solve_537_from_static.py')
s=p.read_text(encoding='utf-8')
old="== b'Find me!'"
new="== b'You Find'"
assert old in s
p.write_text(s.replace(old,new),encoding='utf-8')
print('corrected adjacent bytes: alphabet + 0x40 begins prompt text You Find me!')
