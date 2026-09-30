import ctypes, calendar, datetime
libc=ctypes.CDLL(None)
libc.srand.argtypes=[ctypes.c_uint]
target=bytes.fromhex("720B4455C91B6A024135343386B6679D")
start=calendar.timegm(datetime.datetime(2025,10,12).timetuple())
end=calendar.timegm(datetime.datetime(2025,10,15).timetuple())
found=None
for seed in range(start,end):
    libc.srand(seed)
    for _ in range(16): libc.rand()
    pt=bytes(libc.rand() & 255 for _ in range(16))
    if pt==target:
        found=seed; print("MATCH seed",seed,datetime.datetime.fromtimestamp(seed,datetime.timezone.utc).isoformat()); break
print("searched seeds",end-start,"match",found)
