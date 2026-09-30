import contextlib, io, runpy
output = io.StringIO()
with contextlib.redirect_stdout(output):
    ns = runpy.run_path(r'C:\Users\mzj\Desktop\CTF\玄机刷题\题目资料\题目分类\逆向工程\PaluMaze_551\solve_maze.py')
order = ns['best'][2]
exits = ns['exits']
paths = ns['paths']
segments = [paths[0][exits[i]] if k == 0 else paths[order[k - 1] + 1][exits[i]] for k, i in enumerate(order)]
print('best_cost=', ns['best'][0])
print('route_len=', len(ns['best'][1]))
print('order_indices=', order)
print('segment_lengths=', [len(s) for s in segments])
print('segment_sum=', sum(map(len, segments)))
print('segments_join_route=', ''.join(segments) == ns['best'][1])
print('route=', ns['best'][1])
