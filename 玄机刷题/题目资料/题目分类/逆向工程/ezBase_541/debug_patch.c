#include <windows.h>
#include <stdio.h>
#include <stdint.h>
static int patch_alignment_fault(HANDLE p, ULONG_PTR a) {
    unsigned char old[8], replacement[8]; SIZE_T got=0,wrote=0; int index=-1; unsigned char value=0;
    if(!ReadProcessMemory(p,(LPCVOID)a,old,sizeof(old),&got)||got<5){printf("ReadProcessMemory instruction failed=%lu bytes=%llu\n",GetLastError(),(unsigned long long)got);return 0;}
    printf("FAULT_INSTRUCTION address=%p bytes=",(void*)a);for(int j=0;j<5;j++)printf("%02x",old[j]);printf("\n");
    if(old[0]==0x66&&old[1]==0x0f&&(old[2]==0x6f||old[2]==0x7f)){index=0;value=0xf3;}
    else if(old[0]==0x0f&&old[1]==0x28){index=1;value=0x10;}
    else if(old[0]==0x0f&&old[1]==0x29){index=1;value=0x11;}
    else if(old[0]==0x66&&old[1]==0x0f&&(old[2]==0x6e||old[2]==0x7e)){index=0;value=0xf3;}
    if(index<0){printf("No known aligned-SIMD instruction patch matches.\n");return 0;}
    DWORD protect=0,back=0;BOOL p1=VirtualProtectEx(p,(LPVOID)a,5,PAGE_EXECUTE_READWRITE,&protect);replacement[index]=value;BOOL p2=p1&&WriteProcessMemory(p,(LPVOID)(a+index),&replacement[index],1,&wrote);if(p2)FlushInstructionCache(p,(LPCVOID)a,5);BOOL p3=p1&&VirtualProtectEx(p,(LPVOID)a,5,protect,&back);
    printf("PATCH aligned-SIMD-to-unaligned address=%p index=%d byte=0x%02x protect_ok=%d oldprotect=0x%lx write_ok=%d bytes=%llu restore_ok=%d restored_protect=0x%lx\n",(void*)a,index,value,p1,protect,p2,(unsigned long long)wrote,p3,back);
    return p2&&wrote==1;
}
int main(int argc,char**argv){
 if(argc<3){printf("usage: ezpatch.exe <exe> <stdin-file>\n");return 2;} SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,TRUE};HANDLE hin=CreateFileA(argv[2],GENERIC_READ,FILE_SHARE_READ,&sa,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);if(hin==INVALID_HANDLE_VALUE){printf("stdin open error=%lu\n",GetLastError());return 3;}
 STARTUPINFOA si;PROCESS_INFORMATION pi;ZeroMemory(&si,sizeof(si));ZeroMemory(&pi,sizeof(pi));si.cb=sizeof(si);si.dwFlags=STARTF_USESTDHANDLES;si.hStdInput=hin;si.hStdOutput=GetStdHandle(STD_OUTPUT_HANDLE);si.hStdError=GetStdHandle(STD_ERROR_HANDLE);char cmd[4096];snprintf(cmd,sizeof(cmd),"\"%s\"",argv[1]);printf("COMMAND: CreateProcessA %s DEBUG_ONLY_THIS_PROCESS\n",argv[1]);
 if(!CreateProcessA(argv[1],cmd,NULL,NULL,TRUE,DEBUG_ONLY_THIS_PROCESS|CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){printf("CreateProcess error=%lu\n",GetLastError());CloseHandle(hin);return 4;}CloseHandle(hin);int done=0,n=0,patched=0;while(!done&&n++<10000){DEBUG_EVENT e;if(!WaitForDebugEvent(&e,5000)){printf("WaitForDebugEvent error=%lu\n",GetLastError());break;}DWORD c=DBG_CONTINUE;
 if(e.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT){printf("CREATE_PROCESS base=%p start=%p\n",e.u.CreateProcessInfo.lpBaseOfImage,e.u.CreateProcessInfo.lpStartAddress);if(e.u.CreateProcessInfo.hFile)CloseHandle(e.u.CreateProcessInfo.hFile);}
 else if(e.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT){if(e.u.LoadDll.hFile)CloseHandle(e.u.LoadDll.hFile);}
 else if(e.dwDebugEventCode==EXCEPTION_DEBUG_EVENT){DWORD code=e.u.Exception.ExceptionRecord.ExceptionCode;ULONG_PTR a=(ULONG_PTR)e.u.Exception.ExceptionRecord.ExceptionAddress;printf("EXCEPTION code=0x%08lx address=%p chance=%lu info0=0x%llx info1=0x%llx\n",code,(void*)a,e.u.Exception.dwFirstChance,(unsigned long long)e.u.Exception.ExceptionRecord.ExceptionInformation[0],(unsigned long long)e.u.Exception.ExceptionRecord.ExceptionInformation[1]);if(code==EXCEPTION_BREAKPOINT||code==EXCEPTION_SINGLE_STEP)c=DBG_CONTINUE;else if(code==0xc0000005&&patched<64&&patch_alignment_fault(pi.hProcess,a)){patched++;c=DBG_CONTINUE;}else c=DBG_EXCEPTION_NOT_HANDLED;}
 else if(e.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT){printf("EXIT_PROCESS code=0x%08lx\n",e.u.ExitProcess.dwExitCode);done=1;}
 if(!ContinueDebugEvent(e.dwProcessId,e.dwThreadId,c)){printf("ContinueDebugEvent failed=%lu\n",GetLastError());break;}}
 DWORD ec=0;GetExitCodeProcess(pi.hProcess,&ec);printf("debug_exit=%lu events=%d done=%d patched=%d\n",ec,n,done,patched);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);return 0;
}
