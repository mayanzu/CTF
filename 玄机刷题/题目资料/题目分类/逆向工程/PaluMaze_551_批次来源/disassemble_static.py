from pathlib import Path
import dis,marshal
co=marshal.loads(Path(__file__).with_name('game.bin').read_bytes())
out=[]
def walk(c,depth=0):
 out.append('\n'+'='*100)
 out.append('  '*depth+f'CODE {c.co_name} line={c.co_firstlineno} names={c.co_names} vars={c.co_varnames}')
 out.append('  '*depth+'CONSTANTS: '+repr(c.co_consts))
 out.append(dis.Bytecode(c).dis())
 for x in c.co_consts:
  if hasattr(x,'co_code'):
   walk(x,depth+1)
walk(co)
Path(__file__).with_name('disassembly.txt').write_text('\n'.join(out),encoding='utf-8')
print('saved',len('\n'.join(out)),'chars to disassembly.txt')
print('\n'.join(out[-1:]))
