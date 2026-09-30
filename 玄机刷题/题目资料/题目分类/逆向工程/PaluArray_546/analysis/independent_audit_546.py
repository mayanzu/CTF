from pathlib import Path
import hashlib,struct,zipfile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_OP_MEM
from capstone.x86_const import X86_REG_RIP
root=Path(__file__).resolve().parents[1]; z=zipfile.ZipFile(root/'originals'/'PaluArray_flag.zip'); orig=(root/'extracted'/'PaluArray_flag.exe').read_bytes(); unpack=(root/'analysis'/'PaluArray_flag_unpacked_repro.exe').read_bytes()
pe=struct.unpack_from('<I',unpack,0x3c)[0]; opt=pe+24; image=struct.unpack_from('<Q',unpack,opt+24)[0]; sh=opt+struct.unpack_from('<H',unpack,pe+20)[0]; sections=[]
for i in range(struct.unpack_from('<H',unpack,pe+6)[0]):
 s=sh+40*i; name=unpack[s:s+8].split(b'\0')[0].decode();vs,va,rs,rp=struct.unpack_from('<IIII',unpack,s+8);sections.append((name,va,rs,rp,vs))
def rvaoff(r):
 for name,va,rs,rp,vs in sections:
  if va<=r<va+rs:return rp+r-va
 raise ValueError(hex(r))
def zstr(r,encoding='utf-16le'):
 o=rvaoff(r);end=o
 if encoding=='utf-16le':
  while unpack[end:end+2]!=b'\0\0':end+=2
 else:
  while unpack[end:end+1]!=b'\0':end+=1
 return unpack[o:end].decode(encoding)
print('original_zip_member_bytes_match_extracted=',z.read('PaluArray_flag.exe')==orig)
print('original_exe_sha256=',hashlib.sha256(orig).hexdigest().upper())
print('unpacked_exe_sha256=',hashlib.sha256(unpack).hexdigest().upper())
print('rva_5e50_to_5e90_hex=',unpack[rvaoff(0x5e50):rvaoff(0x5e90)].hex())
print('ascii_error_at_5e58=',zstr(0x5e58,'ascii'))
print('utf16_if_misread_from_5e66=',zstr(0x5e66))
alphabet=zstr(0x5e68); target=zstr(0x5ea0); prefix=zstr(0x5e90); suffix=zstr(0x5e8c); title=zstr(0x5e80)
print('global_init_code_rva_0x1040_table_arg_rva=0x5e68')
print('actual_initializer_source_table=',repr(alphabet),'length=',len(alphabet),'ordinals=',list(enumerate(alphabet)))
print('target=',target,'len=',len(target))
print('prefix=',prefix,'suffix=',suffix,'dialog_title=',title)
candidate=''.join(alphabet[int(c)] for c in target)
forward=''.join(str(alphabet.find(c)) for c in candidate)
print('candidate=',candidate)
print('candidate_hex=',candidate.encode('ascii').hex())
print('per_char=',[(i,int(d),candidate[i],alphabet.find(candidate[i])) for i,d in enumerate(target)])
print('forward=',forward,'match=',forward==target)
digest=hashlib.md5(candidate.encode('ascii')).hexdigest();flag=prefix+digest+suffix
print('md5_ascii=',digest)
print('program_wrapper_value=',flag)
old='PPu_PuP!P!6Pg'; print('prior_candidate=',old,'its_forward_under_actual_table=',''.join(str(alphabet.find(c)) for c in old))
print('prior_candidate_contains_absent_g=', 'g' in old, 'g_find=',alphabet.find('g'))
assert alphabet=='Palu_996!?' and target=='1145141919810'
assert forward==target and hashlib.md5(candidate.encode('ascii')).hexdigest()==digest
assert alphabet.find('9')==5 and alphabet[6]=='9'
assert 'g' not in alphabet and alphabet.find('g')==-1
# Literal xrefs in the unpacked code: constructor arg to alphabet global and MD5 wrapper.
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True;text=next(x for x in sections if x[0]=='.text'); name,va,rs,rp,_=text
want={0x140000000+0x5e68:'alphabet initializer source',0x140000000+0x5ea0:'index target',0x140000000+0x5e8c:'suffix',0x140000000+0x5e90:'prefix',0x140000000+0x5e80:'dialog title'}
print('code_xrefs:')
for ins in md.disasm(unpack[rp:rp+rs],image+va):
 for op in ins.operands:
  if op.type==CS_OP_MEM and op.mem.base==X86_REG_RIP:
   dest=ins.address+ins.size+op.mem.disp
   if dest in want:print(f'  ins_rva={ins.address-image:#x} -> data_rva={dest-image:#x} {want[dest]}: {ins.mnemonic} {ins.op_str}')
