from pathlib import Path
import marshal,types
root=marshal.loads(Path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\PaluMaze_551_fresh\archive\game').read_bytes())
allnames=set(); strings=[]
def walk(code,depth=0):
 pad='  '*depth
 print(f'{pad}CODE name={code.co_name!a} firstline={code.co_firstlineno} args={code.co_varnames[:code.co_argcount]!a} names={code.co_names!a}')
 allnames.update(code.co_names)
 for i,c in enumerate(code.co_consts):
  if isinstance(c,types.CodeType):walk(c,depth+1)
  elif isinstance(c,str):
   print(f'{pad}  STRING[{i}]={c!a}'); strings.append(c)
  elif c is not None and isinstance(c,(int,float,bytes,tuple)):
   print(f'{pad}  CONST[{i}]={c!a}')
walk(root)
print('UNION_NAMES=',sorted(allnames))
print('FLAG_PATH_LITERAL=',any('/flag' in x.lower() for x in strings))
print('MD5_LITERAL=',any('md5' in x.lower() for x in strings))
