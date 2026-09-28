import os, subprocess, time
exe = '/mnt/c/Users/mzj/Desktop/CTF/note_563_binary.tmp'
outfile = '/tmp/analysis/note_unpacked_mem.elf'
p = subprocess.Popen([exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
time.sleep(0.25)
print('子进程 PID:', p.pid)
maps = open(f'/proc/{p.pid}/maps', encoding='utf-8').read().splitlines()
fd = os.open(f'/proc/{p.pid}/mem', os.O_RDONLY)
base = None
for line in maps:
    parts = line.split(None, 5)
    lo, hi = (int(x, 16) for x in parts[0].split('-'))
    label = parts[5] if len(parts) > 5 else ''
    if not label:
        head = os.pread(fd, 4, lo)
        if head == b'\x7fELF':
            base = lo
            print('发现解包 ELF 头:', hex(base), '映射:', line)
            break
if base is None:
    print('未在匿名映射找到 ELF magic')
else:
    chunks = []
    expected = base
    with open(outfile, 'wb') as out:
        for line in maps:
            parts = line.split(None, 5)
            lo, hi = (int(x, 16) for x in parts[0].split('-'))
            label = parts[5] if len(parts) > 5 else ''
            if lo < base or lo >= base + 0x20000 or label:
                continue
            if lo > expected:
                break
            data = os.pread(fd, hi - lo, lo)
            out.seek(lo - base)
            out.write(data)
            expected = hi
            chunks.append((lo, hi, len(data), line))
    print('导出文件:', outfile, '字节数:', os.path.getsize(outfile))
    for chunk in chunks:
        print('导出映射:', chunk)
    for args in (['/usr/bin/readelf', '-h', '-S', outfile], ['/usr/bin/strings', '-a', '-n', '4', outfile], ['/usr/bin/objdump', '-d', '-Mintel', outfile]):
        print('=== 执行:', ' '.join(args), '===')
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors='replace')
        lines = result.stdout.splitlines()
        print('\n'.join(lines[:350]))
        if len(lines) > 350:
            print(f'...输出截断：共 {len(lines)} 行')
        print('退出代码:', result.returncode)
os.close(fd)
p.kill()
p.wait()
print('子进程 returncode:', p.returncode)

