import random,itertools,hashlib
from collections import deque
N=32; random.seed(5822171); maze=[[1]*N for _ in range(N)]; maze[1][1]=0
carve=((0,2),(2,0),(0,-2),(-2,0))
def dig(x,y):
 dirs=list(carve); random.shuffle(dirs)
 for dx,dy in dirs:
  xx,yy=x+dx,y+dy
  if 0<xx<N-1 and 0<yy<N-1 and maze[xx][yy]==1:
   maze[x+dx//2][y+dy//2]=0; maze[xx][yy]=0; dig(xx,yy)
dig(1,1)
exits=[(1,N-2),(N-2,N-2),(N-2,N//2),(N-2,1),(N//2,1)]
for x,y in exits:
 for dx,dy in ((0,1),(1,0),(0,-1),(-1,0)):
  xx,yy=x+dx,y+dy
  if 0<=xx<N and 0<=yy<N:maze[xx][yy]=0
 maze[x][y]=2
labels=[(-1,0,'w'),(0,-1,'a'),(1,0,'s'),(0,1,'d')]
rows=[]
for order in itertools.permutations(labels):
 index={p:i for i,p in enumerate(exits)}; start=((1,1),0); q=deque([start]); prev={start:None}; incoming={}; goal=None
 while q:
  pos,mask=q.popleft()
  if mask==31:goal=(pos,mask); break
  x,y=pos
  for dx,dy,key in order:
   nxt=(x+dx,y+dy)
   if not(0<=nxt[0]<N and 0<=nxt[1]<N) or maze[nxt[0]][nxt[1]]==1:continue
   nm=mask|((1<<index[nxt]) if nxt in index else 0); state=(nxt,nm)
   if state not in prev:prev[state]=(pos,mask);incoming[state]=key;q.append(state)
 rev=[]; state=goal
 while prev[state] is not None:rev.append(incoming[state]);state=prev[state]
 route=''.join(reversed(rev)); digest=hashlib.md5(route.encode('ascii')).hexdigest()
 rows.append((''.join(x[2] for x in order),len(route),digest,route))
print('direction_order_count=',len(rows),'unique_routes=',len({r[3] for r in rows}),'lengths=',sorted({r[1] for r in rows}))
for order,length,digest,route in rows:print('order=',order,'length=',length,'md5=',digest)
for order in ('wasd','asdw','dwas','sawd','dsaw','wdsa'):
 row=next(r for r in rows if r[0]==order)
 print('example',order,'route=',row[3])
