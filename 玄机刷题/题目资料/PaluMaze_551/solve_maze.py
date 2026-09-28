import hashlib
import random
from collections import deque

SIZE = 32
SEED = 5822171

def generate_maze(size=SIZE, seed=SEED):
    random.seed(seed)
    maze = [[1 for _ in range(size)] for _ in range(size)]
    maze[1][1] = 0
    def carve_path(x, y):
        directions = [(0, 2), (2, 0), (0, -2), (-2, 0)]
        random.shuffle(directions)
        for dx, dy in directions:
            new_x, new_y = x + dx, y + dy
            if 0 < new_x < size - 1 and 0 < new_y < size - 1 and maze[new_x][new_y] == 1:
                maze[x + dx // 2][y + dy // 2] = 0
                maze[new_x][new_y] = 0
                carve_path(new_x, new_y)
    carve_path(1, 1)
    exits = [(1, size - 2), (size - 2, size - 2), (size - 2, size // 2), (size - 2, 1), (size // 2, 1)]
    for x, y in exits:
        for dx, dy in ((0, 1), (1, 0), (0, -1), (-1, 0)):
            nx, ny = x + dx, y + dy
            if 0 <= nx < size and 0 <= ny < size:
                maze[nx][ny] = 0
        maze[x][y] = 2
    return maze, exits

def bfs(maze, start):
    q = deque([start])
    prev = {start: None}
    move_for = {}
    for_pos = [(-1, 0, 'w'), (0, -1, 'a'), (1, 0, 's'), (0, 1, 'd')]
    while q:
        x, y = q.popleft()
        for dx, dy, key in for_pos:
            nx, ny = x + dx, y + dy
            if 0 <= nx < len(maze) and 0 <= ny < len(maze[nx]) and maze[nx][ny] != 1 and (nx, ny) not in prev:
                prev[(nx, ny)] = (x, y)
                move_for[(nx, ny)] = key
                q.append((nx, ny))
    def path_to(goal):
        if goal not in prev:
            return None
        seq = []
        p = goal
        while prev[p] is not None:
            seq.append(move_for[p])
            p = prev[p]
        return ''.join(reversed(seq))
    return {pos: path_to(pos) for pos in prev}

maze, exits = generate_maze()
start = (1, 1)
points = [start] + exits
paths = [bfs(maze, p) for p in points]
print('SIZE=', SIZE, 'SEED=', SEED)
print('EXITS=', exits)
print('REACHABLE=', [all(paths[i].get(e) is not None for e in exits) for i in range(len(points))])
print('PAIRWISE DISTANCES:')
for i, p in enumerate(points):
    print(p, [len(paths[i][q]) if paths[i].get(q) is not None else None for q in points])

# Held-Karp DP for the shortest walk from start that visits all five exits in any order.
# State (mask,last_exit_index) stores shortest route and its exit-order witness.
dp = {(1 << i, i): (len(paths[0][e]), paths[0][e], (i,)) for i, e in enumerate(exits) if paths[0].get(e) is not None}
for mask_size in range(1, len(exits) + 1):
    states = [(mask, last, value) for (mask, last), value in list(dp.items()) if mask.bit_count() == mask_size]
    for mask, last, (cost, route, order) in states:
        for nxt in range(len(exits)):
            if mask & (1 << nxt):
                continue
            segment = paths[last + 1].get(exits[nxt])
            if segment is None:
                continue
            new_mask = mask | (1 << nxt)
            candidate = (cost + len(segment), route + segment, order + (nxt,))
            key = (new_mask, nxt)
            if key not in dp or candidate[0] < dp[key][0]:
                dp[key] = candidate
full = (1 << len(exits)) - 1
best = min((v for (mask, _), v in dp.items() if mask == full), key=lambda x: x[0])
route = best[1]
print('EXIT_ORDER=', [exits[i] for i in best[2]])
print('SHORTEST_LENGTH=', len(route))
print('ROUTE=', route)
print('MD5_ASCII_ROUTE=', hashlib.md5(route.encode('ascii')).hexdigest())
# replay the route under the game's coordinate convention and confirm all exits are entered
pos = start
visited = []
for step_no, key in enumerate(route, 1):
    dx, dy = {'w':(-1,0), 'a':(0,-1), 's':(1,0), 'd':(0,1)}[key]
    pos = pos[0] + dx, pos[1] + dy
    if pos in exits and pos not in visited:
        visited.append(pos)
print('REPLAY_FINAL_POSITION=', pos)
print('REPLAY_VISITED_EXITS=', visited)
print('REPLAY_STEPS=', len(route))
print('MAZE: # wall, space corridor, E exit')
for x, row in enumerate(maze):
    print(''.join('#' if v == 1 else 'E' if v == 2 else ' ' for v in row))
