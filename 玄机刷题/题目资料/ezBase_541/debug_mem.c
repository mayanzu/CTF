#include <windows.h>
#include <stdio.h>
#include <stdint.h>
static ULONG_PTR base=0;
int main(int argc,char**argv){
 if(argc<3)return 2; SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,TRUE};HANDLE hin=CreateFileA(argv[2],GENERIC_READ,FILE_SHARE_READ,&sa,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);if(hin==INVALID_HANDLE_VALUE)return 3;
 STARTUPINFOA si;PROCESS_INFORMATION pi;ZeroMemory(&si,sizeof(si));ZeroMemory(&pi,sizeof(pi));si.cb=sizeof(si);si.dwFlags=STARTF_USESTDHANDLES;si.hStdInput=hin;si.hStdOutput=GetStdHandle(STD_OUTPUT_HANDLE);si.hStdError=GetStdHandle(STD_ERROR_HANDLE);
 char cmd[4096];snprintf(cmd,sizeof(cmd),"\"%s\"",argv[1]);printf("COMMAND: CreateProcessA %s DEBUG_ONLY_THIS_PROCESS\n",argv[1]);if(!CreateProcessA(argv[1],cmd,NULL,NULL,TRUE,DEBUG_ONLY_THIS_PROCESS|CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){printf("CreateProcess error=%lu\n",GetLastError());return 4;}CloseHandle(hin);
 int done=0,n=0;while(!done&&n++<10000){DEBUG_EVENT e;if(!WaitForDebugEvent(&e,5000)){printf("wait_error=%lu\n",GetLastError());break;}DWORD c=DBG_CONTINUE;
 if(e.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT){base=(ULONG_PTR)e.u.CreateProcessInfo.lpBaseOfImage;printf("CREATE_PROCESS base=%p start=%p\n",(void*)base,e.u.CreateProcessInfo.lpStartAddress);if(e.u.CreateProcessInfo.hFile)CloseHandle(e.u.CreateProcessInfo.hFile);}
 else if(e.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT){if(e.u.LoadDll.hFile)CloseHandle(e.u.LoadDll.hFile);}
 else if(e.dwDebugEventCode==EXCEPTION_DEBUG_EVENT){DWORD code=e.u.Exception.ExceptionRecord.ExceptionCode;printf("EXCEPTION code=0x%08lx addr=%p chance=%lu\n",code,e.u.Exception.ExceptionRecord.ExceptionAddress,e.u.Exception.dwFirstChance);if(code==EXCEPTION_BREAKPOINT||code==EXCEPTION_SINGLE_STEP)c=DBG_CONTINUE;else{HANDLE th=OpenThread(THREAD_GET_CONTEXT|THREAD_QUERY_INFORMATION,FALSE,e.dwThreadId);if(th){CONTEXT t;ZeroMemory(&t,sizeof(t));t.ContextFlags=CONTEXT_FULL;if(GetThreadContext(th,&t)){printf("CONTEXT RIP=%p RSP=%p RBP=%p RAX=%p RCX=%p RDX=%p RSI=%p RDI=%p\n",(void*)t.Rip,(void*)t.Rsp,(void*)t.Rbp,(void*)t.Rax,(void*)t.Rcx,(void*)t.Rdx,(void*)t.Rsi,(void*)t.Rdi);unsigned char b[256];SIZE_T got=0;LPCVOID p=(LPCVOID)(base+0x1000);if(ReadProcessMemory(pi.hProcess,p,b,sizeof(b),&got)){printf("UNPACKED_AT_RVA1000 length=%llu hex=",(unsigned long long)got);for(SIZE_T j=0;j<got;j++)printf("%02x",b[j]);printf("\n");}else printf("ReadProcessMemory unpacked failed=%lu\n",GetLastError());}CloseHandle(th);}c=DBG_EXCEPTION_NOT_HANDLED;}}
 else if(e.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT){printf("EXIT_PROCESS code=0x%08lx\n",e.u.ExitProcess.dwExitCode);done=1;}
 if(!ContinueDebugEvent(e.dwProcessId,e.dwThreadId,c)){printf("continue_error=%lu\n",GetLastError());break;}}
 DWORD ec=0;GetExitCodeProcess(pi.hProcess,&ec);printf("debug_exit=%lu events=%d done=%d\n",ec,n,done);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);return 0;
}
