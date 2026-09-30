import hashlib
patterns=['137524860','1,3,7,5,2,4,8,6,0','012345678','0,1,2,3,4,5,6,7,8']
suffix='Harmony5337'
for pattern in patterns:
    raw=pattern+suffix
    print('password_repr=',repr(pattern),'md5_input=',repr(raw),'md5=',hashlib.md5(raw.encode()).hexdigest(),'flag=flag{'+hashlib.md5(raw.encode()).hexdigest()+'}')
