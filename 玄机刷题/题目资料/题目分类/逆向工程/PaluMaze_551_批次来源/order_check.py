from pathlib import Path
import random,collections,itertools
N=32; exits=[(1,30),(30,30),(30,16),(30,1),(16,1)]
D=[('w',-1,0),('a',0,-1),('s',1,0),('d',0,1)]
r=random.Random(5822171);m=[[1]*N for _ in range(N)];m[1][1]=3
def carve(x,y):
 ds=[(0,2),(2,0),(0,-2),(-2,0)];r.shuffle(ds)
 for dx,dy in ds:
  nx,ny=x+dx,y+dy
  if 0<=nx<N-1 and 0<=ny<N-1 and m[nx][ny]==1:
   m[x+dx//2][y+dy//2]=0;m[nx][ny]=0;carve(nx,ny)
carve(1,1)
for x,y in exits:
 for dx,dy in [(0,1),(1,0),(0,-1),(-1,0)]:
  nx,ny=x+dx,y+dy
  if 0<=nx<N and 0<=ny<N:m[nx][ny]=0
 m[x][y]=2
idx={p:i for i,p in enumerate(exits)}
# A strict declared-first-visit order is not a game rule; calculate only for contrast.
start=(1,1,0);q=collections.deque([start]);dist={start:0};parent={}
while q:
 x,y,k=q.popleft()
 if k==5:break
 for ch,dx,dy in D:
  p=(x+dx,y+dy)
  if not(0<=p[0]<N and 0<=p[1]<N) or m[p[0]][p[1]]==1:continue
  j=idx.get(p)
  if j is not None and j!=k:continue
  nk=k+1 if j is not None else k
  s=(p[0],p[1],nk)
  if s not in dist:dist[s]=dist[(x,y,k)]+1;parent[s]=((x,y,k),ch);q.append(s)
goal=next((s for s in dist if s[2]==5),None)
if goal:
 path=[];g=goal
 while g!=start:g,c=parent[g];path.append(c)
 print('strict_declared_first_visit_order_distance',dist[goal],'route',''.join(reversed(path)))
else:print('strict declared order unreachable')
# Shortest route with no required exit order is part of the prior logged candidate computation.
print('declared_order',exits)
print('actual_valid_shortest_orders=(exit indexes 4,3,2,1,0) or (4,3,1,2,0)')
