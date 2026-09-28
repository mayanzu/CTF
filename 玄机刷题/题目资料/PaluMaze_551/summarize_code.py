from pathlib import Path
import marshal, types
root = marshal.loads(Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluMaze_551\extracted\game').read_bytes())
def visit(c, depth=0):
    pad='  '*depth
    print(f'{pad}{c.co_name} line={c.co_firstlineno} vars={c.co_varnames} free={c.co_freevars} cell={c.co_cellvars} names={c.co_names}')
    for n,x in enumerate(c.co_consts):
        if isinstance(x,types.CodeType):
            visit(x,depth+1)
        else:
            print(f'{pad}  const[{n}]={ascii(x)}')
visit(root)
