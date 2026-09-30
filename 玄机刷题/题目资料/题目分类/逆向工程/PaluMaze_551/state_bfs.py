import contextlib, hashlib, io, runpy
from collections import deque
capture=io.StringIO()
with contextlib.redirect_stdout(capture):
    ns=runpy.run_path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\PaluMaze_551\solve_maze.py')
maze, exits = ns['maze'], ns['exits']
index={p:i for i,p in enumerate(exits)}
start=(1,1)
orders=[('w,a,s,d',[(-1,0,'w'),(0,-1,'a'),(1,0,'s'),(0,1,'d')]),('w,s,a,d',[(-1,0,'w'),(1,0,'s'),(0,-1,'a'),(0,1,'d')]),('d,s,a,w',[(0,1,'d'),(1,0,'s'),(0,-1,'a'),(-1,0,'w')]),('w,d,s,a',[(-1,0,'w'),(0,1,'d'),(1,0,'s'),(0,-1,'a')]),('a,w,d,s',[(0,-1,'a'),(-1,0,'w'),(0,1,'d'),(1,0,'s')])]
def solve(directions):
    initial=(start,0)
    queue=deque([initial]); previous={initial:None}; incoming={}
    goal=None
    while queue:
        state=queue.popleft(); pos,mask=state
        if mask==(1<<len(exits))-1:
            goal=state; break
        x,y=pos
        for dx,dy,key in directions:
            nxt=(x+dx,y+dy)
            if not (0<=nxt[0]<len(maze) and 0<=nxt[1]<len(maze[nxt[0]])) or maze[nxt[0]][nxt[1]]==1:
                continue
            next_mask=mask | ((1<<index[nxt]) if nxt in index else 0)
            ns=(nxt,next_mask)
            if ns not in previous:
                previous[ns]=state; incoming[ns]=key; queue.append(ns)
    if goal is None: return None
    path=[]; state=goal
    while previous[state] is not None:
        path.append(incoming[state]); state=previous[state]
    path=''.join(reversed(path))
    return path,goal[0]
for name,directions in orders:
    route,final=solve(directions)
    print(name,'length=',len(route),'md5=',hashlib.md5(route.encode()).hexdigest(),'final=',final,'route=',route)
