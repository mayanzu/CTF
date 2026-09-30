from pathlib import Path
import marshal
from xdis import get_opcode_module
from xdis.version_info import PythonImplementation
from xdis.disasm import Bytecode
co=marshal.loads(Path(__file__).with_name('game.bin').read_bytes())
op=get_opcode_module((3,11),PythonImplementation.CPython)
def walk(c):
 yield c
 for x in c.co_consts:
  if hasattr(x,'co_code'): yield from walk(x)
parts=[]
for c in walk(co):
 if c.co_name in ('generate_maze','carve_path','move','get_player_pos','main'):
  parts.append(f'### {c.co_name} line={c.co_firstlineno} names={c.co_names} vars={c.co_varnames} free={c.co_freevars} consts={ascii(c.co_consts)}')
  parts.append(Bytecode(c,op).dis())
text='\n'.join(parts)
Path(__file__).with_name('xdis311.txt').write_text(text,encoding='utf-8')
print('Saved',len(text),'chars')
print(text[:16000])
