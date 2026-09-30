import random,hashlib,collections,json
D=[('w',-1,0),('a',0,-1),('s',1,0),('d',0,1)]
def make(seed=5822171):
 r=random.Random(seed);n=32;m=[[1]*n for _ in range(n)];m[1][1]=3
 def carve(x,y):
  ds=[(0,2),(2,0),(0,-2),(-2,0)];r.shuffle(ds)
  for dx,dy in ds:
   nx,ny=x+dx,y+dy
   if 0<=nx<n-1 and 0<=ny<n-1 and m[nx][ny]==1:
    m[x+dx//2][y+dy//2]=0;m[nx][ny]=0;carve(nx,ny)
 carve(1,1)
 ex=[(1,n-2),(n-2,n-2),(n-2,n//2),(n-2,1),(n//2,1)]
 for x,y in ex:
  for dx,dy in [(0,1),(1,0),(0,-1),(-1,0)]:
   nx,ny=x+dx,y+dy
   if 0<=nx<n and 0<=ny<n:m[nx][ny]=0
  m[x][y]=2
 return m,ex
m,ex=make(); ix={p:i for i,p in enumerate(ex)}; start=(1,1)
q=collections.deque([(1,1,0)]); dist={(1,1,0):0};pred=collections.defaultdict(list)
goal_d=None
while q:
 x,y,mask=q.popleft(); st=(x,y,mask);d=dist[st]
 if goal_d is not None and d>goal_d:break
 if mask==31:goal_d=d;continue
 for ch,dx,dy in D:
  np=(x+dx,y+dy)
  if 0<=np[0]<32 and 0<=np[1]<32 and m[np[0]][np[1]]!=1:
   nm=mask | (1<<ix[np]) if np in ix else mask
   ns=(np[0],np[1],nm)
   if ns not in dist:
    dist[ns]=d+1;pred[ns].append((st,ch));q.append(ns)
   elif dist[ns]==d+1:pred[ns].append((st,ch))
goals=[s for s,d in dist.items() if s[2]==31 and d==goal_d]
paths=[]
def unwind(st, suffix):
 if dist[st]==0:
  paths.append(suffix[::-1]);return
 for ps,ch in pred[st]:unwind(ps,suffix+ch)
for g in goals:unwind(g,'')
paths=sorted(set(paths))
def order(path):
 x,y=start;got=[]
 for ch in path:
  dx,dy=next((dx,dy) for c,dx,dy in D if c==ch);x+=dx;y+=dy
  if (x,y) in ix and ix[(x,y)] not in got:got.append(ix[(x,y)])
 return tuple(got)
counts=collections.Counter(order(p) for p in paths)
print('distance',goal_d,'goal_states',len(goals),'paths',len(paths),'orders',len(counts))
for seq,c in counts.most_common(): print('order',seq,'count',c)
print('ordered-exit paths',sum(c for s,c in counts.items() if s==(0,1,2,3,4)))
print('canonical path wasd lexical',paths[0]);print('canonical md5',hashlib.md5(paths[0].encode()).hexdigest())
print('canonical order',order(paths[0]))
print('first20 hashes+orders')
for p in paths[:20]:print(hashlib.md5(p.encode()).hexdigest(),order(p),p)
