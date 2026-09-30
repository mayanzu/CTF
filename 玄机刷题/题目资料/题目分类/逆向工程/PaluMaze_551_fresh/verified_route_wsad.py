from collections import deque
import hashlib, random
SIZE=32
SEED=5822171
CARVE=((0,2),(2,0),(0,-2),(-2,0))
EXITS=[(1,30),(30,30),(30,16),(30,1),(16,1)]
MOVES=[(-1,0,'w'),(1,0,'s'),(0,-1,'a'),(0,1,'d')]  # exact if/elif order in game move()
random.seed(SEED)
maze=[[1 for _ in range(SIZE)] for _ in range(SIZE)]
maze[1][1]=3
def carve(x,y):
    directions=list(CARVE)
    random.shuffle(directions)
    for dx,dy in directions:
        nx,ny=x+dx,y+dy
        if 0<nx<SIZE-1 and 0<ny<SIZE-1 and maze[nx][ny]==1:
            maze[x+dx//2][y+dy//2]=0
            maze[nx][ny]=0
            carve(nx,ny)
carve(1,1)
for x,y in EXITS:
    for dx,dy in ((0,1),(1,0),(0,-1),(-1,0)):
        nx,ny=x+dx,y+dy
        if 0<=nx<SIZE and 0<=ny<SIZE:
            maze[nx][ny]=0
    maze[x][y]=2
index={point:i for i,point in enumerate(EXITS)}
start=((1,1),0)
queue=deque([start])
parent={start:None}
incoming={}
goal=None
while queue:
    state=queue.popleft()
    (x,y),mask=state
    if mask==31:
        goal=state
        break
    for dx,dy,key in MOVES:
        nx,ny=x+dx,y+dy
        if not (0<=nx<SIZE and 0<=ny<SIZE) or maze[nx][ny]==1:
            continue
        newmask=mask | ((1<<index[(nx,ny)]) if (nx,ny) in index else 0)
        nxt=((nx,ny),newmask)
        if nxt not in parent:
            parent[nxt]=state
            incoming[nxt]=key
            queue.append(nxt)
if goal is None: raise SystemExit('no path found')
steps=[]
state=goal
while parent[state] is not None:
    steps.append(incoming[state])
    state=parent[state]
route=''.join(reversed(steps))
digest=hashlib.md5(route.encode('ascii')).hexdigest()
position=(1,1)
visited=[]
visit_steps=[]
for i,key in enumerate(route,1):
    dx,dy=next((dx,dy) for dx,dy,c in MOVES if c==key)
    nxt=(position[0]+dx,position[1]+dy)
    if not (0<=nxt[0]<SIZE and 0<=nxt[1]<SIZE) or maze[nxt[0]][nxt[1]]==1:
        raise SystemExit(f'invalid wall step {i}: {key} to {nxt}')
    if maze[nxt[0]][nxt[1]]==2:
        visited.append(nxt)
        visit_steps.append((i,nxt))
    position=nxt
print('source_model=Python 3.11 disassembly; solver uses BFS FIFO and move() if/elif order w,s,a,d')
print('size=',SIZE,'seed=',SEED,'start=',(1,1))
print('declared_exits=',EXITS)
print('move_priority=',[m[2] for m in MOVES])
print('shortest_length=',len(route))
print('route=',route)
print('route_ascii_md5=',digest)
print('candidate_flag=flag{'+digest+'}')
print('exit_visit_sequence=',visit_steps)
print('unique_exit_count=',len(set(visited)))
print('final_position=',position)
