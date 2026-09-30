import contextlib, io, runpy, itertools, hashlib
from collections import deque
base = r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\PaluMaze_551\solve_maze.py'
with contextlib.redirect_stdout(io.StringIO()): ns=runpy.run_path(base)
maze, exits = ns['maze'], ns['exits']
lookup={p:i for i,p in enumerate(exits)}
steps=[(-1,0,'w'),(0,-1,'a'),(1,0,'s'),(0,1,'d')]
rows=[]
for perm in itertools.permutations(steps):
    q=deque([((1,1),0)]); prev={((1,1),0):None}; incoming={}; goal=None
    while q:
        pos,mask=q.popleft()
        if mask==31: goal=(pos,mask); break
        for dx,dy,key in perm:
            nxt=(pos[0]+dx,pos[1]+dy)
            if not (0<=nxt[0]<32 and 0<=nxt[1]<32) or maze[nxt[0]][nxt[1]]==1: continue
            newmask=mask|((1<<lookup[nxt]) if nxt in lookup else 0)
            state=(nxt,newmask)
            if state not in prev:
                prev[state]=(pos,mask); incoming[state]=key; q.append(state)
    route=[]; state=goal
    while prev[state] is not None: route.append(incoming[state]); state=prev[state]
    route=''.join(reversed(route))
    rows.append((''.join(x[2] for x in perm),len(route),hashlib.md5(route.encode('ascii')).hexdigest(),route))
print('permutation_count=',len(rows))
print('unique_route_count=',len({r[3] for r in rows}))
print('route_lengths=',sorted({r[1] for r in rows}))
for order,length,digest,route in rows:
    print(f'order={order} length={length} md5={digest} route={route}')
