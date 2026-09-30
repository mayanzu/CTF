import hashlib,itertools,time
wanted='871f72716d85a6374f438ea70c2fd62c'
suffix='Harmony5337'
start=time.perf_counter(); count=0; found=[]
for length in range(4,10):
    for tup in itertools.permutations('012345678',length):
        raw=''.join(tup)
        count+=1
        if hashlib.md5((raw+suffix).encode()).hexdigest()==wanted:
            found.append(('joined',raw))
        if hashlib.md5((',' .join(tup)+suffix).encode()).hexdigest()==wanted:
            found.append(('comma',','.join(tup)))
print('tested',count,'unique digit sequences lengths 4..9 in joined/comma format')
print('matches',found)
print('elapsed_seconds',round(time.perf_counter()-start,3))
