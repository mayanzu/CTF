#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
static void dump_stack(HANDLE p, ULONG_PTR sp) {
    uint64_t words[32]; SIZE_T got=0;
    if(!ReadProcessMemory(p,(LPCVOID)sp,words,sizeof(words),&got)){printf("ReadProcessMemory stack failed=%lu\n",GetLastError());return;}
    printf("STACK rsp=%p read=%llu\n",(void*)sp,(unsigned long long)got);
    for(size_t i=0;i<got/8;i++) printf("  +0x%02zx: 0x%016llx\n",i*8,(unsigned long long)words[i]);
}
static void module_for(HANDLE p, ULONG_PTR a) {
    HMODULE m[512]; DWORD cb=0; if(!EnumProcessModules(p,m,sizeof(m),&cb)){printf("EnumProcessModules error=%lu\n",GetLastError());return;}
    unsigned n=cb/sizeof(HMODULE);if(n>512)n=512;
    for(unsigned i=0;i<n;i++){MODULEINFO mi;char path[MAX_PATH]="";if(GetModuleInformation(p,m[i],&mi,sizeof(mi))&&a>=(ULONG_PTR)mi.lpBaseOfDll&&a<(ULONG_PTR)mi.lpBaseOfDll+mi.SizeOfImage){DWORD k=GetModuleFileNameExA(p,m[i],path,sizeof(path));printf("MODULE path=%s path_chars=%lu base=%p rva=0x%llx\n",path,k,mi.lpBaseOfDll,(unsigned long long)(a-(ULONG_PTR)mi.lpBaseOfDll));return;}}
    printf("MODULE unknown address=%p module_count=%u\n",(void*)a,n);
}
int main(int argc,char**argv){
    if(argc<3){fprintf(stderr,"usage: ezstack.exe <program.exe> <stdin-file>\n");return 2;}
    SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,TRUE};HANDLE hin=CreateFileA(argv[2],GENERIC_READ,FILE_SHARE_READ,&sa,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);if(hin==INVALID_HANDLE_VALUE){printf("input open error=%lu\n",GetLastError());return 3;}
    STARTUPINFOA si;PROCESS_INFORMATION pi;ZeroMemory(&si,sizeof(si));ZeroMemory(&pi,sizeof(pi));si.cb=sizeof(si);si.dwFlags=STARTF_USESTDHANDLES;si.hStdInput=hin;si.hStdOutput=GetStdHandle(STD_OUTPUT_HANDLE);si.hStdError=GetStdHandle(STD_ERROR_HANDLE);
    char cmd[4096];snprintf(cmd,sizeof(cmd),"\"%s\"",argv[1]);printf("COMMAND: CreateProcessA %s DEBUG_ONLY_THIS_PROCESS\n",argv[1]);
    if(!CreateProcessA(argv[1],cmd,NULL,NULL,TRUE,DEBUG_ONLY_THIS_PROCESS|CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){printf("CreateProcess error=%lu\n",GetLastError());return 4;}CloseHandle(hin);
    int done=0,events=0;while(!done&&events++<10000){DEBUG_EVENT e;if(!WaitForDebugEvent(&e,5000)){printf("WaitForDebugEvent error=%lu\n",GetLastError());break;}DWORD c=DBG_CONTINUE;
      if(e.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT){printf("CREATE_PROCESS base=%p start=%p\n",e.u.CreateProcessInfo.lpBaseOfImage,e.u.CreateProcessInfo.lpStartAddress);if(e.u.CreateProcessInfo.hFile)CloseHandle(e.u.CreateProcessInfo.hFile);}
      else if(e.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT){if(e.u.LoadDll.hFile)CloseHandle(e.u.LoadDll.hFile);}
      else if(e.dwDebugEventCode==EXCEPTION_DEBUG_EVENT){DWORD x=e.u.Exception.ExceptionRecord.ExceptionCode;ULONG_PTR a=(ULONG_PTR)e.u.Exception.ExceptionRecord.ExceptionAddress;printf("EXCEPTION code=0x%08lx addr=%p chance=%lu info0=0x%llx info1=0x%llx\n",x,(void*)a,e.u.Exception.dwFirstChance,(unsigned long long)e.u.Exception.ExceptionRecord.ExceptionInformation[0],(unsigned long long)e.u.Exception.ExceptionRecord.ExceptionInformation[1]);
        if(x==EXCEPTION_BREAKPOINT||x==EXCEPTION_SINGLE_STEP)c=DBG_CONTINUE;else{HANDLE th=OpenThread(THREAD_GET_CONTEXT|THREAD_QUERY_INFORMATION,FALSE,e.dwThreadId);if(th){CONTEXT t;ZeroMemory(&t,sizeof(t));t.ContextFlags=CONTEXT_FULL;if(GetThreadContext(th,&t)){printf("CONTEXT RIP=%p RSP=%p RBP=%p RAX=%p RBX=%p RCX=%p RDX=%p RSI=%p RDI=%p\n",(void*)t.Rip,(void*)t.Rsp,(void*)t.Rbp,(void*)t.Rax,(void*)t.Rbx,(void*)t.Rcx,(void*)t.Rdx,(void*)t.Rsi,(void*)t.Rdi);module_for(pi.hProcess,t.Rip);dump_stack(pi.hProcess,t.Rsp);}CloseHandle(th);}c=DBG_EXCEPTION_NOT_HANDLED;}}
      else if(e.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT){printf("EXIT_PROCESS code=0x%08lx\n",e.u.ExitProcess.dwExitCode);done=1;}
      if(!ContinueDebugEvent(e.dwProcessId,e.dwThreadId,c)){printf("ContinueDebugEvent error=%lu\n",GetLastError());break;}}
    DWORD code=0;GetExitCodeProcess(pi.hProcess,&code);printf("debug_exit=%lu events=%d done=%d\n",code,events,done);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);return 0;
}
