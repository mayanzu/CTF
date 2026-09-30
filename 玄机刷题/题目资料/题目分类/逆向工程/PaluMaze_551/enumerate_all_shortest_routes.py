import contextlib,io,runpy,hashlib
from collections import deque,defaultdict
base=r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluMaze_551\solve_maze.py'
with contextlib.redirect_stdout(io.StringIO()): ns=runpy.run_path(base)
maze,exits=ns['maze'],ns['exits']; idx={p:i for i,p in enumerate(exits)}
moves=[(-1,0,'w'),(0,-1,'a'),(1,0,'s'),(0,1,'d')]
start=((1,1),0); dist={start:0}; prev=defaultdict(list); q=deque([start]); best=None
while q:
    state=q.popleft(); pos,mask=state; d=dist[state]
    if best is not None and d>=best: continue
    for dx,dy,key in moves:
        nxt=(pos[0]+dx,pos[1]+dy)
        if not (0<=nxt[0]<32 and 0<=nxt[1]<32) or maze[nxt[0]][nxt[1]]==1: continue
        nm=mask|((1<<idx[nxt]) if nxt in idx else 0); ns2=(nxt,nm); nd=d+1
        if ns2 not in dist:
            dist[ns2]=nd; prev[ns2].append((state,key)); q.append(ns2)
        elif dist[ns2]==nd: prev[ns2].append((state,key))
        if nm==31: best=nd if best is None else min(best,nd)
goals=[s for s,d in dist.items() if s[1]==31 and d==best]
cache={start:['']}
def paths_to(state):
    if state in cache:return cache[state]
    out=[]
    for parent,key in prev[state]:out.extend(prefix+key for prefix in paths_to(parent))
    cache[state]=out
    return out
routes=[route for goal in goals for route in paths_to(goal)]
digests={hashlib.md5(r.encode('ascii')).hexdigest() for r in routes}
print('minimum_length=',best,'goal_states=',len(goals))
print('shortest_routes=',len(routes),'unique_route_strings=',len(set(routes)),'unique_md5=',len(digests))
print('first_route=',routes[0])
print('first_route_md5=',hashlib.md5(routes[0].encode()).hexdigest())
print('last_route=',routes[-1])
print('last_route_md5=',hashlib.md5(routes[-1].encode()).hexdigest())
print('md5_of_decimal_length=',hashlib.md5(str(best).encode('ascii')).hexdigest())
