from pathlib import Path
import dis,marshal
co=marshal.loads(Path(__file__).with_name('game.bin').read_bytes())

def all_codes(c):
 yield c
 for x in c.co_consts:
  if hasattr(x,'co_code'):
   yield from all_codes(x)
for c in all_codes(co):
 if c.co_name in ('generate_maze','carve_path','move','print_maze','get_player_pos','main'):
  print('\n###',c.co_name,'line',c.co_firstlineno,'names=',c.co_names,'vars=',c.co_varnames,'free=',c.co_freevars,'cell=',c.co_cellvars)
  print('consts=',ascii(c.co_consts))
  for i in dis.get_instructions(c):
   if i.opname != 'CACHE': print(f'{i.offset:4} {i.starts_line or 0:4} {i.opname:24} {ascii(i.argrepr)}')
