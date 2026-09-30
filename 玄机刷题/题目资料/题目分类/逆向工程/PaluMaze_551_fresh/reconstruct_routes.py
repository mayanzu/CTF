# Reconstructed only from the fresh attachment's marshaled game code constants.
# This script does not execute game_flag.exe.
import hashlib, random
from collections import deque, defaultdict

SIZE=32
SEED=5822171
CARVE_STEPS=((0,2),(2,0),(0,-2),(-2,0))
OPEN_NEIGHBORS=((0,1),(1,0),(0,-1),(-1,0))
EXITS_FORMULA='[(1,n-2),(n-2,n-2),(n-2,n//2),(n-2,1),(n//2,1)]'

def build_maze(width=SIZE,height=SIZE,seed=SEED):
    n=min(width,height)
    random.seed(seed)
    maze=[[1 for _ in range(n)] for _ in range(n)]
    maze[1][1]=0
    def carve(x,y):
        directions=list(CARVE_STEPS)
        random.shuffle(directions)
        for dx,dy in directions:
            nx,ny=x+dx,y+dy
            if 0<nx<n-1 and 0<ny<n-1 and maze[nx][ny]==1:
                maze[x+dx//2][y+dy//2]=0
                maze[nx][ny]=0
                carve(nx,ny)
    carve(1,1)
    exits=[(1,n-2),(n-2,n-2),(n-2,n//2),(n-2,1),(n//2,1)]
    for x,y in exits:
        for dx,dy in OPEN_NEIGHBORS:
            nx,ny=x+dx,y+dy
            if 0<=nx<n and 0<=ny<n:
                maze[nx][ny]=0
        maze[x][y]=2
    return maze,exits

maze,exits=build_maze()
index={p:i for i,p in enumerate(exits)}
step_order=[(-1,0,'w'),(0,-1,'a'),(1,0,'s'),(0,1,'d')]
start=((1,1),0)
distance={start:0}
parents=defaultdict(list)
queue=deque([start])
minimum=None
while queue:
    state=queue.popleft(); (x,y),mask=state; d=distance[state]
    if minimum is not None and d>=minimum:
        continue
    for dx,dy,key in step_order:
        nx,ny=x+dx,y+dy
        if not(0<=nx<SIZE and 0<=ny<SIZE) or maze[nx][ny]==1:
            continue
        newmask=mask | ((1<<index[(nx,ny)]) if (nx,ny) in index else 0)
        nxt=((nx,ny),newmask); nd=d+1
        if nxt not in distance:
            distance[nxt]=nd; parents[nxt].append((state,key)); queue.append(nxt)
        elif distance[nxt]==nd:
            parents[nxt].append((state,key))
        if newmask==(1<<len(exits))-1:
            minimum=nd if minimum is None else min(minimum,nd)
goals=[s for s,d in distance.items() if s[1]==(1<<len(exits))-1 and d==minimum]
cache={start:['']}
def reconstruct(state):
    if state in cache:return cache[state]
    routes=[]
    for prior,key in parents[state]:
        routes.extend(prefix+key for prefix in reconstruct(prior))
    cache[state]=routes
    return routes
routes=[p for goal in goals for p in reconstruct(goal)]
print('source=game_flag (1).exe static reconstructed model')
print('size=',SIZE,'seed=',SEED)
print('carve_steps=',CARVE_STEPS)
print('exit_coordinates=',exits)
print('exit_adjacent_open_order=',OPEN_NEIGHBORS)
print('minimum_steps=',minimum)
print('goal_states=',[g[0] for g in goals])
print('shortest_route_count=',len(routes),'unique_route_count=',len(set(routes)))
route=routes[0]
print('canonical_for_this_script_only=FIFO BFS; move order w,a,s,d')
print('example_route=',route)
print('example_route_md5=',hashlib.md5(route.encode('ascii')).hexdigest())
print('example_flag_candidate=flag{'+hashlib.md5(route.encode('ascii')).hexdigest()+'}')
print('not_platform_verified=True')
route=routes[0]
position=(1,1); seen=[]; at=[]
for step_number,key in enumerate(route,1):
    dx,dy={'w':(-1,0),'a':(0,-1),'s':(1,0),'d':(0,1)}[key]
    position=(position[0]+dx,position[1]+dy)
    if position in index and position not in seen:
        seen.append(position); at.append((step_number,position))
print('route_replay_steps=',len(route))
print('route_replay_exit_visits=',at)
print('route_replay_final_position=',position)
