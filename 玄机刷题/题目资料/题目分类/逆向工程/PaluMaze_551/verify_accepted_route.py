"""Reproduce the CPython 3.11 PaluMaze logic statically; does not run game_flag.exe."""
import hashlib
import random
from collections import deque

SIZE = 32
SEED = 5_822_171
# This is the branch order in move(): w, then s, then a, then d.
DIRECTIONS = [('w', -1, 0), ('s', 1, 0), ('a', 0, -1), ('d', 0, 1)]
EXIT_ARRAY = [(1, SIZE - 2), (SIZE - 2, SIZE - 2),
              (SIZE - 2, SIZE // 2), (SIZE - 2, 1),
              (SIZE // 2, 1)]

def build_maze():
    random.seed(SEED)
    maze = [[1 for _ in range(SIZE)] for _ in range(SIZE)]
    maze[1][1] = 3  # player

    def carve_path(x, y):
        directions = [(0, 2), (2, 0), (0, -2), (-2, 0)]
        random.shuffle(directions)
        for dx, dy in directions:
            nx, ny = x + dx, y + dy
            if 0 < nx < SIZE - 1 and 0 < ny < SIZE - 1 and maze[nx][ny] == 1:
                maze[x + dx // 2][y + dy // 2] = 0
                maze[nx][ny] = 0
                carve_path(nx, ny)

    carve_path(1, 1)
    for x, y in EXIT_ARRAY:
        for dx, dy in [(0, 1), (1, 0), (0, -1), (-1, 0)]:
            nx, ny = x + dx, y + dy
            if 0 <= nx < SIZE and 0 <= ny < SIZE:
                maze[nx][ny] = 0
        maze[x][y] = 2
    return maze

def bfs_shortest_route(maze):
    exit_index = {pos: i for i, pos in enumerate(EXIT_ARRAY)}
    start = (1, 1, 0)
    queue = deque([start])
    distance = {start: 0}
    ways = {start: 1}
    previous = {}
    goal_distance = None
    goals = []
    while queue:
        x, y, mask = queue.popleft()
        state = (x, y, mask)
        d = distance[state]
        if goal_distance is not None and d > goal_distance:
            break
        if mask == (1 << len(EXIT_ARRAY)) - 1:
            goal_distance = d
            goals.append(state)
            continue
        for key, dx, dy in DIRECTIONS:
            nx, ny = x + dx, y + dy
            if not (0 <= nx < SIZE and 0 <= ny < SIZE):
                continue
            if maze[nx][ny] == 1:  # move() rejects only wall value 1
                continue
            next_mask = mask | (1 << exit_index[(nx, ny)]) if (nx, ny) in exit_index else mask
            next_state = (nx, ny, next_mask)
            if next_state not in distance:
                distance[next_state] = d + 1
                ways[next_state] = ways[state]
                previous[next_state] = (state, key)
                queue.append(next_state)
            elif distance[next_state] == d + 1:
                ways[next_state] += ways[state]
    route_count = sum(ways[state] for state in goals)
    goal = goals[0]
    reversed_route = []
    while goal != start:
        goal, key = previous[goal]
        reversed_route.append(key)
    route = ''.join(reversed(reversed_route))
    return goal_distance, route_count, route

def replay_with_move_logic(initial_maze, route):
    maze = [row[:] for row in initial_maze]
    position = (1, 1)
    visited = []
    visits = []
    for step, key in enumerate(route, 1):
        _, dx, dy = next(item for item in DIRECTIONS if item[0] == key)
        new_pos = (position[0] + dx, position[1] + dy)
        assert 0 <= new_pos[0] < SIZE and 0 <= new_pos[1] < SIZE
        assert maze[new_pos[0]][new_pos[1]] != 1, (step, new_pos, maze[new_pos[0]][new_pos[1]])
        maze[position[0]][position[1]] = 0
        if maze[new_pos[0]][new_pos[1]] == 2:
            visited.append(new_pos)
            visits.append((step, new_pos, EXIT_ARRAY.index(new_pos)))
            maze[new_pos[0]][new_pos[1]] = 4
        maze[new_pos[0]][new_pos[1]] = 3
        position = new_pos
    assert len(visited) == 5
    return position, visits

maze = build_maze()
shortest, count, route = bfs_shortest_route(maze)
final_pos, visits = replay_with_move_logic(maze, route)
assert shortest == 295
assert len(route) == 295
assert hashlib.md5(route.encode('ascii')).hexdigest() == '634e3323bef7c35e91078eb19cb31210'
print(f'input_file=game_flag.exe; sha256=319DE70C476CC7C2761A57D88B83A5529D2DEA53C1F73DC23926D21ABC86EE019')
print(f'grid={SIZE}x{SIZE}; seed={SEED}; start=(1,1)')
print('direction_tiebreak_order=' + ''.join(item[0] for item in DIRECTIONS))
print('direction_deltas=' + repr({key: (dx, dy) for key, dx, dy in DIRECTIONS}))
print('exit_array=' + repr(EXIT_ARRAY))
print(f'shortest_length={shortest}; number_of_shortest_move_strings={count}')
print('route_length=' + str(len(route)))
print('route=' + route)
print('route_md5_ascii_lowercase=' + hashlib.md5(route.encode('ascii')).hexdigest())
print('flag=flag{' + hashlib.md5(route.encode('ascii')).hexdigest() + '}')
print('visited_exit_trace=' + repr(visits))
print('visited_exit_coordinates=' + repr([pos for _, pos, _ in visits]))
print('final_position=' + repr(final_pos))
print('replay_step_count=' + str(len(route)))
print('replay_all_5_exits=True')
