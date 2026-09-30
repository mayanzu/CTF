from pathlib import Path
import struct,zlib,binascii
p=Path(__file__).resolve().parents[1]/'附件'/'challenge.png'; b=p.read_bytes()
print('file bytes=',len(b),'PNG signature=',b[:8].hex())
# PNG chunks including CRC and exact IEND boundary.
o=8; chunks=[]
while o+12<=len(b) and b[o:o+4]!=b'PK\x03\x04':
    n=struct.unpack_from('>I',b,o)[0]; typ=b[o+4:o+8]; data=b[o+8:o+8+n]; crc=struct.unpack_from('>I',b,o+8+n)[0]
    calc=binascii.crc32(typ+data)&0xffffffff
    chunks.append((o,typ.decode(),n,crc==calc)); o+=12+n
    if typ==b'IEND': break
print('PNG chunks=',chunks,'end_offset=',o,'trailing_len=',len(b)-o,'trailing_head=',b[o:o+16].hex())
# ZIP local header fields.
zoff=b.index(b'PK\x03\x04',o)
(local,need,flags,method,tm,dt,crc,csize,usize,fnl,exl)=struct.unpack_from('<IHHHHHIIIHH',b,zoff)
fn=b[zoff+30:zoff+30+fnl]; extra=b[zoff+30+fnl:zoff+30+fnl+exl]
doff=zoff+30+fnl+exl
print('local_header=',{'offset':zoff,'version_needed':need,'flags':hex(flags),'encrypted':bool(flags&1),'data_descriptor':bool(flags&8),'method':method,'dos_time':hex(tm),'dos_date':hex(dt),'crc32':f'{crc:08x}','crc_check_byte':f'{crc>>24:02x}','compressed_including_crypto_header':csize,'uncompressed':usize,'filename':fn.decode(),'extra_len':exl,'data_offset':doff,'enc_header':b[doff:doff+12].hex(),'deflate_cipher_len':csize-12})
print('local_extra=',extra.hex())
# Locate central directory and EOCD.
cd=b.index(b'PK\x01\x02',doff+csize); eocd=b.index(b'PK\x05\x06',cd)
(sig,made,need2,flags2,method2,tm2,dt2,crc2,cs2,us2,fnl2,exl2,cl2,disk,iattr,eattr,loff)=struct.unpack_from('<IHHHHHHIIIHHHHHII',b,cd)
fn2=b[cd+46:cd+46+fnl2]; ex2=b[cd+46+fnl2:cd+46+fnl2+exl2]; comment=b[cd+46+fnl2+exl2:cd+46+fnl2+exl2+cl2]
e=struct.unpack_from('<IHHHHIIH',b,eocd)
print('central=',{'offset':cd,'made_by':made,'version_needed':need2,'flags':hex(flags2),'method':method2,'crc32':f'{crc2:08x}','compressed':cs2,'uncompressed':us2,'filename':fn2.decode(),'extra_len':exl2,'comment_len':cl2,'local_offset':loff,'extra':ex2.hex(),'comment':comment.hex(),'external_attr':hex(eattr)})
print('EOCD=',{'offset':eocd,'comment_len':e[7],'end_offset':eocd+22+e[7],'file_end':len(b),'trailing_after_eocd':len(b)-(eocd+22+e[7])})
print('local/central agree=',(flags,method,crc,csize,usize,fn)==(flags2,method2,crc2,cs2,us2,fn2))
# Candidate DEFLATE prefixes conditional on an assumed text prefix and compressor mode.
for prefix in (b'flag{',b'xj{',b'ctf{'):
    sample=prefix+b'A'*(usize-len(prefix)-1)+b'}'
    for level in (1,6,9):
        c=zlib.compressobj(level,zlib.DEFLATED,-15)
        raw=c.compress(sample)+c.flush()
        print('conditional_deflate=',prefix.decode(),'level=',level,'len=',len(raw),'first12=',raw[:12].hex(),'BFINAL=',raw[0]&1,'BTYPE=',(raw[0]>>1)&3)
