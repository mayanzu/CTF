import hashlib, pathlib, struct
p = pathlib.Path(__file__).resolve().parents[1] / 'extracted' / 'CatchPalu_flag.exe'
b = p.read_bytes()
def u16(o): return struct.unpack_from('<H', b, o)[0]
def u32(o): return struct.unpack_from('<I', b, o)[0]
assert b[:2] == b'MZ' and b[u32(0x3c):u32(0x3c)+4] == b'PE\0\0'
pe = u32(0x3c); coff = pe+4; nsec=u16(coff+2); opt=coff+20; osz=u16(coff+16)
assert u16(opt)==0x10b, 'expected PE32'
sects=[]
for n in range(nsec):
 o=opt+osz+40*n; name=b[o:o+8].split(b'\0')[0].decode(); vs,va,rs,rp=struct.unpack_from('<IIII',b,o+8); sects.append((name,va,vs,rp,rs))
def rva_to_off(rva):
 if rva<u32(opt+60): return rva
 for name,va,vs,rp,rs in sects:
  if va <= rva < va+max(vs,rs): return rp+rva-va
 raise ValueError(hex(rva))
def cstr_va(va):
 o=rva_to_off(va-0x400000); e=b.index(0,o); return b[o:e]
key=cstr_va(0x404108)
expected=cstr_va(0x404078)
dis_path=pathlib.Path(__file__).resolve().parent/'disassembly.txt'
dis=dis_path.read_text(encoding='utf-8',errors='replace')
assert '401750:' in dis and '0x404078' in dis and '401768:' in dis and 'cmp    al,BYTE PTR [ecx]' in dis
assert '401732:' in dis and '0x4040a4' in dis and '401743:' in dis and '0x404090' in dis
# 25 consecutive 7-byte `mov byte ptr [ebp+disp32],imm8` instructions at VA 0x4013bf.
start=rva_to_off(0x13bf)
ct=[]
for i in range(25):
 ins=b[start+7*i:start+7*(i+1)]
 assert len(ins)==7 and ins[:2]==b'\xc6\x85', (i,ins.hex())
 disp=struct.unpack_from('<i',ins,2)[0]
 assert disp == -0x104+i, (i,hex(disp))
 ct.append(ins[6])
# Reproduce the KSA loop at 0x401100: three full rounds; j=(S[i]+j+K[i mod keylen]) mod 233.
S=list(range(256))
j=0
for _round in range(3):
 for i in range(256):
  j=(S[i]+j+key[i%len(key)])%0xe9
  S[i],S[j]=S[j],S[i]
# Reproduce the stream loop at 0x401270; XOR makes the same operation encrypt/decrypt.
i=j=0; ks=[]; pt=[]
for x in ct:
 i=(i+1)&0xff; j=(j+S[i])&0xff; S[i],S[j]=S[j],S[i]
 t=(S[i]+S[j])&0xff; k=S[t]; ks.append(k); pt.append(x^k)
out=bytes(pt)
def pairwise_compare(inp, exp):
 inp=inp+b'\\x00'; exp=exp+b'\\x00'; pos=0
 while True:
  a=inp[pos] if pos<len(inp) else 0; e=exp[pos] if pos<len(exp) else 0
  if a!=e: return False
  if a==0: return True
  a1=inp[pos+1] if pos+1<len(inp) else 0; e1=exp[pos+1] if pos+1<len(exp) else 0
  if a1!=e1: return False
  pos+=2
  if a1==0: return True
assert pairwise_compare(expected,expected)
assert not pairwise_compare(expected[:-1]+b'X',expected)
assert not pairwise_compare(expected+b'X',expected)
print('PE_SHA256='+hashlib.sha256(b).hexdigest())
print('KEY='+key.decode('ascii')+f' ({len(key)} bytes)')
print('EXPECTED_LITERAL='+expected.decode('ascii')+f' ({len(expected)} bytes)')
print('CIPHERTEXT_LENGTH='+str(len(ct)))
print('CIPHERTEXT_HEX='+' '.join(f'{x:02x}' for x in ct))
print('KEYSTREAM_HEX='+' '.join(f'{x:02x}' for x in ks))
print('DECODED_BYTES='+out.hex())
print('DECODED_TEXT='+out.decode('ascii','backslashreplace'))
decoy=b'palu{G00d_P1au_Kn0w_H00K}'
print('FLAG_FILE_OFFSET=0x'+format(rva_to_off(0x4078),'x'))
print('FLAG_LITERAL_HEX='+expected.hex())
print('FLAG_LITERAL='+expected.decode('ascii'))
print('COMPARE_ASSEMBLY_EVIDENCE=PASS (input at 0x401732, echo at 0x401743, expected pointer at 0x401750, byte compare at 0x401768)')
print('FLAG_LENGTH='+str(len(expected)))
print('COMPARATOR_SIMULATION=PASS (exact match true; one-byte mutation and trailing byte false)')
print('FLAG_DIRECT_COMPARE_SOURCE=0x404078 (see main function 0x401750/0x401768 in disassembly.txt)')
print('DECRYPTED_HOOK_TEXT='+out.decode('ascii'))
print('DECRYPTED_TEXT_MATCH='+str(out==decoy))
print('DECRYPTED_TEXT_IS_FLAG='+str(out==expected))
assert out==decoy, 'hook-data plaintext mismatch'
assert expected.startswith(b'flag{') and expected.endswith(b'}')
assert len(expected)==23
print('FORMAT_CHECK=PASS (flag{...}; exact comparator target)')





