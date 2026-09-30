import contextlib, hashlib, io, itertools, runpy
f = io.StringIO()
with contextlib.redirect_stdout(f):
    ns = runpy.run_path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\PaluMaze_551\solve_maze.py')
exits, paths = ns['exits'], ns['paths']
records=[]
for order in itertools.permutations(range(len(exits))):
    prev_node = 0
    route = ''
    for idx in order:
        route += paths[prev_node][exits[idx]]
        prev_node = idx + 1
    records.append((len(route), order, route, hashlib.md5(route.encode()).hexdigest()))
minimum = min(r[0] for r in records)
best = [r for r in records if r[0] == minimum]
print('permutations=', len(records))
print('minimum_length=', minimum, 'optimal_order_count=', len(best), 'unique_route_count=', len({r[2] for r in best}))
for length, order, route, digest in best:
    print('order=', order, 'route_length=', length, 'md5=', digest, 'route=', route)
