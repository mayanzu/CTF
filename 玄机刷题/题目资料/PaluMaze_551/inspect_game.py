from pathlib import Path
import dis, marshal, types
source = Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluMaze_551\extracted\game')
root = marshal.loads(source.read_bytes())
print('PYTHON', __import__('sys').version)
print('MAIN', root.co_filename, 'bytes', source.stat().st_size)
def visit(code, depth=0):
    pad = '  ' * depth
    print(f'{pad}FUNCTION {code.co_name} firstlineno={code.co_firstlineno} args={code.co_varnames[:code.co_argcount]} names={code.co_names}')
    for value in code.co_consts:
        if isinstance(value, types.CodeType):
            visit(value, depth + 1)
        elif isinstance(value, (str, int, float, bytes, tuple, list, dict)):
            print(f'{pad}  CONST {value!r}')
    try:
        dis.dis(code)
    except Exception as exc:
        print(f'{pad}DISASSEMBLY_ERROR {type(exc).__name__}: {exc}')
visit(root)
