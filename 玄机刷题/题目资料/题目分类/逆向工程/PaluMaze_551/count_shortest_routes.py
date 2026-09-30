import contextlib,io,runpy
from collections import deque,defaultdict
base=r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\PaluMaze_551\solve_maze.py'
with contextlib.redirect_stdout(io.StringIO()): ns=runpy.run_path(base)
maze,exits=ns['maze'],ns['exits']; idx={p:i for i,p in enumerate(exits)}
moves=[(-1,0,'w'),(0,-1,'a'),(1,0,'s'),(0,1,'d')]
start=((1,1),0); dist={start:0}; ways={start:1}; q=deque([start]); best=None
while q:
    state=q.popleft(); pos,mask=state; d=dist[state]
    if best is not None and d>=best: continue
    for dx,dy,key in moves:
        nxt=(pos[0]+dx,pos[1]+dy)
        if not (0<=nxt[0]<32 and 0<=nxt[1]<32) or maze[nxt[0]][nxt[1]]==1: continue
        nmask=mask|((1<<idx[nxt]) if nxt in idx else 0); nxtstate=(nxt,nmask); nd=d+1
        if nxtstate not in dist:
            dist[nxtstate]=nd; ways[nxtstate]=ways[state]; q.append(nxtstate)
        elif dist[nxtstate]==nd:
            ways[nxtstate]+=ways[state]
        if nmask==31:
            best=nd if best is None else min(best,nd)
goals=[s for s,d in dist.items() if s[1]==31 and d==best]
print('shortest_length=',best)
print('shortest_goal_states=',len(goals))
print('shortest_route_count=',sum(ways[s] for s in goals))
for state in sorted(goals): print('goal=',state[0],'route_count_to_goal=',ways[state])
