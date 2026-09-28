#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void module_for(HANDLE process, ULONG_PTR address) {
    HMODULE mods[512]; DWORD needed=0;
    if(!EnumProcessModules(process,mods,sizeof(mods),&needed)) { printf("EnumProcessModules failed=%lu\n",GetLastError()); return; }
    unsigned n=needed/sizeof(HMODULE); if(n>512)n=512;
    for(unsigned i=0;i<n;i++) {
        MODULEINFO mi; char path[MAX_PATH];
        if(GetModuleInformation(process,mods[i],&mi,sizeof(mi)) && address >= (ULONG_PTR)mi.lpBaseOfDll && address < (ULONG_PTR)mi.lpBaseOfDll+mi.SizeOfImage) {
            GetModuleFileNameExA(process,mods[i],path,sizeof(path));
            printf("FAULT_MODULE path=%s base=%p rva=0x%Ix size=0x%lx\n",path,mi.lpBaseOfDll,address-(ULONG_PTR)mi.lpBaseOfDll,mi.SizeOfImage); return;
        }
    }
    printf("FAULT_MODULE not-found address=%p module_count=%u\n",(void*)address,n);
}
int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr,"usage: ezdebug.exe <program.exe> <stdin-file>\n"); return 2; }
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE hin = CreateFileA(argv[2], GENERIC_READ, FILE_SHARE_READ, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hin == INVALID_HANDLE_VALUE) { fprintf(stderr,"CreateFileA stdin failed: %lu\n",GetLastError()); return 3; }
    STARTUPINFOA si; PROCESS_INFORMATION pi; ZeroMemory(&si,sizeof(si)); ZeroMemory(&pi,sizeof(pi));
    si.cb=sizeof(si); si.dwFlags=STARTF_USESTDHANDLES; si.hStdInput=hin; si.hStdOutput=GetStdHandle(STD_OUTPUT_HANDLE); si.hStdError=GetStdHandle(STD_ERROR_HANDLE);
    char command[4096]; snprintf(command,sizeof(command),"\"%s\"",argv[1]);
    printf("COMMAND: CreateProcessA(application=%s, command=%s, DEBUG_ONLY_THIS_PROCESS)\n",argv[1],command);
    if (!CreateProcessA(argv[1],command,NULL,NULL,TRUE,DEBUG_ONLY_THIS_PROCESS|CREATE_NO_WINDOW,NULL,NULL,&si,&pi)) { fprintf(stderr,"CreateProcessA failed: %lu\n",GetLastError()); CloseHandle(hin); return 4; }
    CloseHandle(hin);
    int done=0, events=0; DWORD exitcode=0;
    while (!done && events++ < 10000) {
        DEBUG_EVENT ev;
        if (!WaitForDebugEvent(&ev,5000)) { fprintf(stderr,"WaitForDebugEvent timeout/error=%lu\n",GetLastError()); break; }
        DWORD status=DBG_CONTINUE;
        switch(ev.dwDebugEventCode) {
          case CREATE_PROCESS_DEBUG_EVENT:
            printf("CREATE_PROCESS base=%p start=%p thread=%lu\n",ev.u.CreateProcessInfo.lpBaseOfImage,ev.u.CreateProcessInfo.lpStartAddress,ev.dwThreadId);
            if(ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile); break;
          case LOAD_DLL_DEBUG_EVENT: {
            char path[MAX_PATH]=""; GetModuleFileNameExA(pi.hProcess,(HMODULE)ev.u.LoadDll.lpBaseOfDll,path,sizeof(path));
            printf("LOAD_DLL base=%p path=%s thread=%lu\n",ev.u.LoadDll.lpBaseOfDll,path,ev.dwThreadId);
            if(ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile); break;
          }
          case EXCEPTION_DEBUG_EVENT: {
            DWORD code=ev.u.Exception.ExceptionRecord.ExceptionCode; ULONG_PTR address=(ULONG_PTR)ev.u.Exception.ExceptionRecord.ExceptionAddress;
            printf("EXCEPTION code=0x%08lx address=%p first_chance=%lu thread=%lu\n",code,(void*)address,ev.u.Exception.dwFirstChance,ev.dwThreadId);
            if(code==EXCEPTION_BREAKPOINT || code==EXCEPTION_SINGLE_STEP) status=DBG_CONTINUE;
            else {
              HANDLE th=OpenThread(THREAD_GET_CONTEXT|THREAD_QUERY_INFORMATION,FALSE,ev.dwThreadId);
              if(th) { CONTEXT c; ZeroMemory(&c,sizeof(c)); c.ContextFlags=CONTEXT_FULL; if(GetThreadContext(th,&c)) { printf("CONTEXT RIP=%p RAX=%p RBX=%p RCX=%p RDX=%p RSI=%p RDI=%p RSP=%p RBP=%p\n",(void*)c.Rip,(void*)c.Rax,(void*)c.Rbx,(void*)c.Rcx,(void*)c.Rdx,(void*)c.Rsi,(void*)c.Rdi,(void*)c.Rsp,(void*)c.Rbp); module_for(pi.hProcess,c.Rip); unsigned char buf[32]; SIZE_T got=0; if(ReadProcessMemory(pi.hProcess,(LPCVOID)(c.Rip-8),buf,sizeof(buf),&got)) { printf("FAULT_BYTES address=%p length=%llu hex=",(void*)(c.Rip-8),(unsigned long long)got); for(SIZE_T j=0;j<got;j++)printf("%02x",buf[j]); printf("\n"); } } else printf("GetThreadContext failed=%lu\n",GetLastError()); CloseHandle(th); }
              status=DBG_EXCEPTION_NOT_HANDLED;
            } break;
          }
          case EXIT_PROCESS_DEBUG_EVENT: exitcode=ev.u.ExitProcess.dwExitCode; printf("EXIT_PROCESS code=0x%08lx (%lu)\n",exitcode,exitcode); done=1; break;
          case OUTPUT_DEBUG_STRING_EVENT: printf("OUTPUT_DEBUG_STRING unicode=%u length=%u\n",ev.u.DebugString.fUnicode,ev.u.DebugString.nDebugStringLength); break;
          default: break;
        }
        fflush(stdout);
        if(!ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,status)){fprintf(stderr,"ContinueDebugEvent failed=%lu\n",GetLastError());break;}
    }
    if(!done){TerminateProcess(pi.hProcess,0xEE);WaitForSingleObject(pi.hProcess,2000);}
    GetExitCodeProcess(pi.hProcess,&exitcode); printf("debugger_exit_code=%lu events=%d done=%d\n",exitcode,events,done);
    CloseHandle(pi.hThread);CloseHandle(pi.hProcess);return done?0:5;
}
