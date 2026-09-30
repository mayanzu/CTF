from pathlib import Path
import marshal,types
p=Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluMaze_551_fresh\archive\game')
root=marshal.loads(p.read_bytes())
allnames=set(); allstrings=[]
def walk(code,depth=0):
    pad='  '*depth
    print(f'{pad}FUNCTION={code.co_name!r} line={code.co_firstlineno} argcount={code.co_argcount}')
    print(f'{pad}  NAMES={code.co_names!r}')
    allnames.update(code.co_names)
    for i,value in enumerate(code.co_consts):
        if isinstance(value,types.CodeType):
            walk(value,depth+1)
        elif isinstance(value,str):
            print(f'{pad}  STRING_CONST[{i}]={value!r}')
            allstrings.append(value)
        elif value is not None and (isinstance(value,(int,float,bytes)) or isinstance(value,tuple)):
            print(f'{pad}  CONST[{i}]={value!r}')
walk(root)
print('ALL_GLOBAL_OR_ATTR_NAMES=',sorted(allnames))
print('STATIC_STRING_HAS_/flag=',any('/flag' in s.lower() for s in allstrings))
print('STATIC_NAME_HAS_FILE_READ=',sorted(n for n in allnames if n.lower() in {'open','read','read_text','read_bytes','pathlib','hashlib','md5'}))
print('STATIC_NAME_HAS_HASH=',sorted(n for n in allnames if 'hash' in n.lower() or n.lower()=='md5'))
