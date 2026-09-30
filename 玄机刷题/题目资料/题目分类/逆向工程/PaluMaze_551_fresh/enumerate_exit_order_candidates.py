import random,itertools,hashlib
from collections import deque
N=32; seed=5822171; carve=((0,2),(2,0),(0,-2),(-2,0)); border=((0,1),(1,0),(0,-1),(-1,0))
random.seed(seed); maze=[[1 for _ in range(N)] for _ in range(N)]; maze[1][1]=0
def dig(x,y):
    dirs=list(carve); random.shuffle(dirs)
    for dx,dy in dirs:
        xx,yy=x+dx,y+dy
        if 0<xx<N-1 and 0<yy<N-1 and maze[xx][yy]==1:
            maze[x+dx//2][y+dy//2]=0; maze[xx][yy]=0; dig(xx,yy)
dig(1,1)
exits=[(1,N-2),(N-2,N-2),(N-2,N//2),(N-2,1),(N//2,1)]
for x,y in exits:
    for dx,dy in border:
        xx,yy=x+dx,y+dy
        if 0<=xx<N and 0<=yy<N:maze[xx][yy]=0
    maze[x][y]=2
moves=[(-1,0,'w'),(0,-1,'a'),(1,0,'s'),(0,1,'d')]
def route_between(start,goal):
    q=deque([start]); prev={start:None}; incoming={}
    while q:
        x,y=q.popleft()
        if (x,y)==goal:break
        for dx,dy,key in moves:
            nxt=(x+dx,y+dy)
            if 0<=nxt[0]<N and 0<=nxt[1]<N and maze[nxt[0]][nxt[1]]!=1 and nxt not in prev:
                prev[nxt]=(x,y); incoming[nxt]=key; q.append(nxt)
    p=goal; rev=[]
    while prev[p] is not None:rev.append(incoming[p]);p=prev[p]
    return ''.join(reversed(rev))
points=[(1,1)]+exits
pair={(a,b):route_between(a,b) for a in points for b in points}
rows=[]
for order in itertools.permutations(range(5)):
    seq=(0,)+tuple(i+1 for i in order)
    route=''.join(pair[(points[seq[i]],points[seq[i+1]])] for i in range(5))
    rows.append((len(route),order,route,hashlib.md5(route.encode('ascii')).hexdigest()))
minimum=min(x[0] for x in rows)
print('declared_exit_order=',exits)
for label,order in [('declared',tuple(range(5))),('reverse_declared',tuple(reversed(range(5))))]:
    item=next(r for r in rows if r[1]==order)
    print(f'{label}_length={item[0]} order={[exits[i] for i in order]} md5={item[3]} route={item[2]}')
best=[r for r in rows if r[0]==minimum]
print('permutations=',len(rows),'minimum_total=',minimum,'minimum_orders=',len(best))
for length,order,route,digest in best:
    print('optimal_order=',[exits[i] for i in order],'length=',length,'md5=',digest,'route=',route)
