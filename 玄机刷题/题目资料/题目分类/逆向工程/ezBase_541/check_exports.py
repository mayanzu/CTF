import struct, pathlib
wanted='''__acrt_iob_func __p___argc __p___argv __p__commode __setusermatherr __stdio_common_vfprintf __stdio_common_vsprintf _c_exit _cexit _configthreadlocale _configure_narrow_argv _crt_at_quick_exit _crt_atexit _execute_onexit_table _exit _get_initial_narrow_environment _initialize_narrow_environment _initialize_onexit_table _initterm _initterm_e _register_onexit_function _register_thread_local_exe_atexit_callback _seh_filter_dll _seh_filter_exe _set_app_type _set_fmode _set_new_mode exit fgets puts strcmp strcspn terminate __C_specific_handler __current_exception __current_exception_context __std_type_info_destroy_list'''.split()
def exports(path):
    b=pathlib.Path(path).read_bytes(); pe=struct.unpack_from('<I',b,0x3c)[0]; coff=pe+4; nsec=struct.unpack_from('<H',b,coff+2)[0]; osz=struct.unpack_from('<H',b,coff+16)[0]; opt=coff+20
    if struct.unpack_from('<H',b,opt)[0]!=0x20b: raise ValueError('not PE32+')
    erva,esz=struct.unpack_from('<II',b,opt+112); st=opt+osz; ss=[]
    for i in range(nsec):
        q=st+40*i; name=b[q:q+8].split(b'\0')[0].decode('ascii','replace'); vs,va,rs,rp=struct.unpack_from('<IIII',b,q+8); ss.append((va,max(vs,rs),rp))
    def off(r):
        for va,size,rp in ss:
            if va<=r<va+size:return rp+r-va
        raise ValueError(hex(r))
    q=off(erva); f=struct.unpack_from('<IIHHIIIIIII',b,q); base,nfunc,nnames,fr,nr,orr=f[5:]
    fs=struct.unpack_from('<'+'I'*nfunc,b,off(fr)); ns=struct.unpack_from('<'+'I'*nnames,b,off(nr)); oo=struct.unpack_from('<'+'H'*nnames,b,off(orr)); result={}
    for r,o in zip(ns,oo):
        p=off(r); e=b.find(b'\0',p); name=b[p:e].decode('ascii','replace'); result[name]=fs[o]
    return result
for name in ['ucrtbase.dll','msvcrt.dll','vcruntime140.dll','kernelbase.dll']:
    p=pathlib.Path(r'C:\Windows\System32')/name
    print('\nDLL',p,'exists',p.exists())
    if not p.exists():continue
    try:
        ex=exports(p); print('export_count',len(ex))
        for n in wanted:
            if n in ex:print(n,hex(ex[n]))
        print('missing=',[n for n in wanted if n not in ex])
    except Exception as e: print('ERROR',type(e).__name__,str(e))
