import random, hashlib, collections
N=32
EXITS=[(1,N-2),(N-2,N-2),(N-2,N//2),(N-2,1),(N//2,1)]
DIRS=[('w',-1,0),('a',0,-1),('s',1,0),('d',0,1)]
def make_maze(seed=5822171):
    rng=random.Random(seed)
    maze=[[1 for _ in range(N)] for _ in range(N)]
    maze[1][1]=3
    def carve(x,y):
        dirs=[(0,2),(2,0),(0,-2),(-2,0)]
        rng.shuffle(dirs)
        for dx,dy in dirs:
            nx,ny=x+dx,y+dy
            if 0<=nx<N-1 and 0<=ny<N-1 and maze[nx][ny]==1:
                maze[x+dx//2][y+dy//2]=0
                maze[nx][ny]=0
                carve(nx,ny)
    carve(1,1)
    for x,y in EXITS:
        for dx,dy in [(0,1),(1,0),(0,-1),(-1,0)]:
            nx,ny=x+dx,y+dy
            if 0<=nx<N and 0<=ny<N:
                maze[nx][ny]=0
        maze[x][y]=2
    return maze

def shortest():
    maze=make_maze(); exitbit={pos:1<<i for i,pos in enumerate(EXITS)}
    start=(1,1,0); q=collections.deque([start]); dist={start:0}; ways={start:1}; parent={}
    goal_dist=None; goals=[]
    while q:
        x,y,mask=q.popleft(); state=(x,y,mask); d=dist[state]
        if goal_dist is not None and d>goal_dist: break
        if mask==31:
            goal_dist=d; goals.append(state); continue
        for ch,dx,dy in DIRS:
            nx,ny=x+dx,y+dy
            if not(0<=nx<N and 0<=ny<N) or maze[nx][ny]==1: continue
            nm=mask|exitbit.get((nx,ny),0)
            nxt=(nx,ny,nm)
            if nxt not in dist:
                dist[nxt]=d+1;ways[nxt]=ways[state];parent[nxt]=(state,ch);q.append(nxt)
            elif dist[nxt]==d+1:
                ways[nxt]+=ways[state]
                parent.setdefault(nxt,(state,ch))
    total=sum(ways[g] for g in goals)
    g=goals[0]; rev=[]
    while g!=start:
        g,ch=parent[g];rev.append(ch)
    path=''.join(reversed(rev))
    return maze,goal_dist,total,path
maze,distance,count,path=shortest()
# Independently validate against the program's move-state transitions.
state=[row[:] for row in maze]; pos=(1,1); visited=[]
for c in path:
    dx,dy=next((dx,dy) for key,dx,dy in DIRS if key==c)
    nxt=(pos[0]+dx,pos[1]+dy)
    assert 0<=nxt[0]<N and 0<=nxt[1]<N
    assert state[nxt[0]][nxt[1]] != 1
    state[pos[0]][pos[1]]=0
    if state[nxt[0]][nxt[1]]==2:
        visited.append(nxt);state[nxt[0]][nxt[1]]=4
    state[nxt[0]][nxt[1]]=3
    pos=nxt
assert distance==295 and len(path)==295 and count==512 and len(visited)==5
print('seed=5822171')
print('start=(1,1)')
print('exit_array_order='+repr(EXITS))
print('input_to_delta='+repr({c:(dx,dy) for c,dx,dy in DIRS}))
print('shortest_steps=',distance)
print('number_of_distinct_shortest_move_strings=',count)
print('first_BFS_route_exit_visit_order='+repr(visited))
print('route_ascii_length=',len(path))
print('route_ascii_lowercase=',path)
print('md5_lowercase_raw=',hashlib.md5(path.encode('ascii')).hexdigest())
print('md5_uppercase_raw=',hashlib.md5(path.upper().encode('ascii')).hexdigest())
print('md5_comma_separated=',hashlib.md5(','.join(path).encode('ascii')).hexdigest())
print('validated_by_transition_simulation=True')
