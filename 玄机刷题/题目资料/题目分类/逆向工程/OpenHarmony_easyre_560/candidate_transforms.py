import base64
hint = b"NzAyZDBlODgxZDNjNzNjOWIzOTBkZjIwNTRiZGQxNWNjY2I"
raw = base64.b64decode(hint + b"="*((-len(hint))%4))
magic = b"`d^ba_^YZZZVWXRRT"
print(f"hint={hint.decode()} length={len(hint)} decoded={raw.decode()} length={len(raw)}")
print(f"magic={magic.decode()} length={len(magic)} reversed={magic[::-1].decode()}")
for name,key in [("magic",magic),("magic_reversed",magic[::-1])]:
  for op in ("xor","add","sub"):
    if op == "xor": out=bytes(c ^ key[i%len(key)] for i,c in enumerate(raw))
    elif op == "add": out=bytes((c + key[i%len(key)])&255 for i,c in enumerate(raw))
    else: out=bytes((c - key[i%len(key)])&255 for i,c in enumerate(raw))
    n=sum(32<=x<127 for x in out)
    print(f"{name:14} {op:3} printable={n}/{len(out)} repr={out!r}")
print("Hint reversed:", raw[::-1].decode())
