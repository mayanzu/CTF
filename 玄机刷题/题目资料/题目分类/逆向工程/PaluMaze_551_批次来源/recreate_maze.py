import random,hashlib,collections
from pathlib import Path
D=[('w',-1,0),('a',0,-1),('s',1,0),('d',0,1)]
def make(seed):
 r=random.Random(seed); n=32; m=[[1]*n for _ in range(n)];m[1][1]=3
 def carve(x,y):
  dirs=[(0,2),(2,0),(0,-2),(-2,0)];r.shuffle(dirs)
  for dx,dy in dirs:
   nx,ny=x+dx,y+dy
   if 0<=nx<n-1 and 0<=ny<n-1 and m[nx][ny]==1:
    m[x+dx//2][y+dy//2]=0;m[nx][ny]=0;carve(nx,ny)
 carve(1,1)
 exits=[(1,n-2),(n-2,n-2),(n-2,n//2),(n-2,1),(n//2,1)]
 for x,y in exits:
  for dx,dy in [(0,1),(1,0),(0,-1),(-1,0)]:
   nx,ny=x+dx,y+dy
   if 0<=nx<n and 0<=ny<n:m[nx][ny]=0
  m[x][y]=2
 return m,exits

def solve(seed):
 m,exits=make(seed); targets={p:i for i,p in enumerate(exits)}
 start=(1,1); mask=1<<targets[start] if start in targets else 0
 q=collections.deque([(start[0],start[1],mask)])
 dist={(start[0],start[1],mask):0};cnt={(start[0],start[1],mask):1};prev={}
 goal=None;goalD=None
 while q:
  x,y,ma=q.popleft();st=(x,y,ma);d=dist[st]
  if goalD is not None and d>goalD:break
  if ma==31:
   goal=st;goalD=d;continue
  for c,dx,dy in D:
   nx,ny=x+dx,y+dy
   if 0<=nx<32 and 0<=ny<32 and m[nx][ny]!=1:
    nm=ma|(1<<targets[(nx,ny)]) if (nx,ny) in targets else ma
    ns=(nx,ny,nm)
    if ns not in dist:
     dist[ns]=d+1;cnt[ns]=cnt[st];prev[ns]=(st,c);q.append(ns)
    elif dist[ns]==d+1:cnt[ns]+=cnt[st]
 if not goal:return None
 total=sum(v for k,v in cnt.items() if k[2]==31 and dist[k]==goalD)
 # canonical shortest under neighbor order
 goals=[k for k in dist if k[2]==31 and dist[k]==goalD]
 g=goals[0];path=[]
 while g in prev:
  p,c=prev[g];path.append(c);g=p
 path=''.join(reversed(path))
 return goalD,total,path,hashlib.md5(path.encode()).hexdigest(),m,exits
for sd in [5822171,0,1,12345]:
 x=solve(sd);print('seed',sd,'distance',x[0],'shortest_paths',x[1],'route_md5',x[3],'first200',x[2][:200]);print('exits',x[5]);print('route length',len(x[2]))
