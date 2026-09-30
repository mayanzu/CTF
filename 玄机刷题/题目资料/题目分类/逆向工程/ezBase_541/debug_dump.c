#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
int main(int argc,char**argv){
 if(argc<4){printf("usage: ezdump.exe <exe> <input> <dump>\n");return 2;}
 SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,TRUE};HANDLE hin=CreateFileA(argv[2],GENERIC_READ,FILE_SHARE_READ,&sa,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);if(hin==INVALID_HANDLE_VALUE){printf("stdin open error=%lu\n",GetLastError());return 3;}
 STARTUPINFOA si;PROCESS_INFORMATION pi;ZeroMemory(&si,sizeof(si));ZeroMemory(&pi,sizeof(pi));si.cb=sizeof(si);si.dwFlags=STARTF_USESTDHANDLES;si.hStdInput=hin;si.hStdOutput=GetStdHandle(STD_OUTPUT_HANDLE);si.hStdError=GetStdHandle(STD_ERROR_HANDLE);
 char cmd[4096];snprintf(cmd,sizeof(cmd),"\"%s\"",argv[1]);printf("COMMAND: CreateProcessA %s DEBUG_ONLY_THIS_PROCESS\n",argv[1]);if(!CreateProcessA(argv[1],cmd,NULL,NULL,TRUE,DEBUG_ONLY_THIS_PROCESS|CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){printf("CreateProcess error=%lu\n",GetLastError());return 4;}CloseHandle(hin);
 ULONG_PTR base=0;int dumped=0,done=0,n=0;while(!done&&n++<10000){DEBUG_EVENT e;if(!WaitForDebugEvent(&e,5000)){printf("wait_error=%lu\n",GetLastError());break;}DWORD c=DBG_CONTINUE;
 if(e.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT){base=(ULONG_PTR)e.u.CreateProcessInfo.lpBaseOfImage;printf("CREATE_PROCESS base=%p start=%p\n",(void*)base,e.u.CreateProcessInfo.lpStartAddress);if(e.u.CreateProcessInfo.hFile)CloseHandle(e.u.CreateProcessInfo.hFile);}
 else if(e.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT){if(e.u.LoadDll.hFile)CloseHandle(e.u.LoadDll.hFile);}
 else if(e.dwDebugEventCode==EXCEPTION_DEBUG_EVENT){DWORD code=e.u.Exception.ExceptionRecord.ExceptionCode;printf("EXCEPTION code=0x%08lx addr=%p chance=%lu\n",code,e.u.Exception.ExceptionRecord.ExceptionAddress,e.u.Exception.dwFirstChance);if(code==EXCEPTION_BREAKPOINT||code==EXCEPTION_SINGLE_STEP)c=DBG_CONTINUE;else{if(!dumped&&code==0xc0000005){dumped=1;const DWORD want=0xb000;unsigned char*buf=(unsigned char*)malloc(want);SIZE_T got=0;LPCVOID from=(LPCVOID)(base+0x1000);if(ReadProcessMemory(pi.hProcess,from,buf,want,&got)){HANDLE hf=CreateFileA(argv[3],GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);if(hf!=INVALID_HANDLE_VALUE){DWORD written=0;BOOL ok=WriteFile(hf,buf,(DWORD)got,&written,NULL);CloseHandle(hf);printf("DUMP path=%s source=%p requested=%lu read=%llu written=%lu ok=%u\n",argv[3],from,want,(unsigned long long)got,written,ok);}else printf("CreateFile dump error=%lu\n",GetLastError());}else printf("ReadProcessMemory dump error=%lu read=%llu\n",GetLastError(),(unsigned long long)got);free(buf);}c=DBG_EXCEPTION_NOT_HANDLED;}}
 else if(e.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT){printf("EXIT_PROCESS code=0x%08lx\n",e.u.ExitProcess.dwExitCode);done=1;}
 if(!ContinueDebugEvent(e.dwProcessId,e.dwThreadId,c)){printf("ContinueDebugEvent error=%lu\n",GetLastError());break;}}
 DWORD ec=0;GetExitCodeProcess(pi.hProcess,&ec);printf("debug_exit=%lu events=%d done=%d dumped=%d\n",ec,n,done,dumped);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);return 0;
}
