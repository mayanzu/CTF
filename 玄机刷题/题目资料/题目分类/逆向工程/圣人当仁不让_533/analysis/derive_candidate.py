import base64,string
ct='z8nO0NTOntKdop6dloqh1Q=='
t=base64.b64decode(ct)
inv=lambda y: (((y-3)&255)^0xaa)
known=bytes(inv(y) for y in t)
alpha='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
print('target:',ct,'length',len(ct))
print('decoded transformed bytes:',t.hex())
print('input[0:16] inverse:',repr(known), 'hex',known.hex())
# The binary writes 4*ceil(n/3) characters, then incorrectly overwrites (encoded_len-(n%3))%4 trailing characters with '='.
# For n=17 it emits two pads. Thus target chars 20 and 21 encode transformed byte 15 and high nibble of transformed byte 16.
q=alpha.index(ct[21])
print('last meaningful Base64 sextet:',ct[21],q,bin(q))
need_hi=q&15
print('required high nibble of transformed input[16]:',hex(need_hi))
def encode_bug(inp):
    out=base64.b64encode(inp).decode()
    pad=(len(out)-(len(inp)%3))&3
    return out[:len(out)-pad]+'='*pad
matches=[]
for c in range(0x20,0x7f):
    y=((c^0xaa)+3)&255
    if (y>>4)==need_hi:
        candidate=known+bytes([c])
        transformed=bytes((((x^0xaa)+3)&255) for x in candidate)
        enc=encode_bug(transformed)
        if enc==ct:
            matches.append((c,candidate,transformed))
print('printable final-byte candidates that forward-encode exactly:')
for c,candidate,transformed in matches:print(f'char={chr(c)!r} input={candidate!r} input_hex={candidate.hex()} transformed={transformed.hex()} forward={encode_bug(transformed)}')
print('match_count',len(matches))
print('strict flag syntax candidates:')
for c,candidate,_ in matches:
    s=candidate.decode('ascii')
    print(repr(s),'opens flag{',s.startswith('flag{'),'closes }',s.endswith('}'),'brace count',s.count('{'),s.count('}'))
