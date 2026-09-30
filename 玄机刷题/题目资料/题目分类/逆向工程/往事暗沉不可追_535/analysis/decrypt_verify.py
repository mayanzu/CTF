from pathlib import Path
import sys
from marshal310 import Code, parse_file

def walk(value):
    if isinstance(value, Code):
        yield value
        for child in value.fields["consts"]:
            yield from walk(child)
    elif isinstance(value, (tuple,list)):
        for child in value: yield from walk(child)

root=parse_file(sys.argv[1])
if not isinstance(root,Code) or root.fields["name"] != "<module>": raise SystemExit("unexpected frozen script root")
consts=root.fields["consts"]
bytecode=next(v for v in consts if isinstance(v,tuple) and v and v[0]=="LOAD")
cipher=next(v for v in consts if isinstance(v,tuple) and v and all(isinstance(x,int) and 0<=x<=255 for x in v))
ops=[(bytecode[i],bytecode[i+1],bytecode[i+2]) for i in range(0,len(bytecode),3)]
assert len(bytecode)%3==0
xor_keys=[arg for op,reg,arg in ops if op=="XOR"]
assert [op for op,reg,arg in ops]==["LOAD","XOR","STORE","LOAD","XOR","STORE"]
assert xor_keys==[0x55,0xaa]
print(f"Embedded bytecode operations: {ops!r}")
print(f"Encrypted byte values ({len(cipher)}): {list(cipher)}")
print(f"XOR immediates: {[hex(k) for k in xor_keys]}; combined key: 0x{__import__('functools').reduce(lambda a,b:a^b,xor_keys,0):02x}")

# Faithful single pass of the frozen VM logic.
memory=[0]*256; registers=[0]*16
memory[16:16+len(cipher)]=cipher
ip=0
while ip<len(bytecode):
    op=bytecode[ip]; reg=bytecode[ip+1]; arg=bytecode[ip+2]
    if op=="LOAD": registers[reg]=memory[arg]
    elif op=="STORE": memory[arg]=registers[reg]
    elif op=="XOR": registers[reg]^=arg
    else: raise ValueError(f"unknown op {op!r}")
    ip+=3
print(f"Exact VM writes: memory[32]={memory[32]} (0x{memory[32]:02x}), memory[48]={memory[48]} (0x{memory[48]:02x})")
print(f"Exact VM leaves memory[16:32] unchanged: {memory[16:32]==list(cipher)}")

# Applying the encoded two-XOR chain to each encrypted data byte yields the full data block.
plain=bytes(__import__('functools').reduce(lambda x,k:x^k,xor_keys,b) for b in cipher)
assert bytes(x^0xff for x in plain)==bytes(cipher)  # independent inverse check
assert plain.decode("ascii")=="flag{7549ecca-f}"
print(f"Elementwise plaintext bytes: {list(plain)}")
print(f"Elementwise plaintext text: {plain.decode('ascii')}")
print(f"Comma-separated decimal candidate: {','.join(map(str,plain))}")