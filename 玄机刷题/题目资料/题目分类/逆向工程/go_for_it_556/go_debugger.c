#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>

#define IMAGE_BASE 0x400000ULL
#define BREAK_RVA  0x9eec0ULL

static void dump32(const char *label, const unsigned char *b) {
    unsigned i;
    printf("%s=", label);
    for (i = 0; i < 32; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(int argc, char **argv) {
    wchar_t app[MAX_PATH], input[MAX_PATH], cmd[32768];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa;
    HANDLE hIn;
    DWORD flags = DEBUG_ONLY_THIS_PROCESS;
    DWORD64 bp = 0;
    unsigned char original = 0, trap = 0xcc;
    int installed = 0, captured = 0, done = 0;

    if (argc != 3) {
        fprintf(stderr, "usage: go_debugger.exe <program.exe> <input.txt>\n");
        return 2;
    }
    if (!MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, app, MAX_PATH) ||
        !MultiByteToWideChar(CP_UTF8, 0, argv[2], -1, input, MAX_PATH)) {
        fprintf(stderr, "path conversion failed: %lu\n", GetLastError());
        return 3;
    }
    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    hIn = CreateFileW(input, GENERIC_READ, FILE_SHARE_READ, &sa, OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL, NULL);
    if (hIn == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateFileW(stdin) failed: %lu\n", GetLastError());
        return 4;
    }
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = hIn;
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    ZeroMemory(&pi, sizeof(pi));
    swprintf(cmd, sizeof(cmd) / sizeof(cmd[0]), L"\"%ls\"", app);
    printf("launch=%ls\n", app);

    if (!CreateProcessW(app, cmd, NULL, NULL, TRUE, flags, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "CreateProcessW failed: %lu\n", GetLastError());
        CloseHandle(hIn);
        return 5;
    }
    CloseHandle(hIn);

    while (!done) {
        DEBUG_EVENT ev;
        DWORD continueStatus = DBG_CONTINUE;
        if (!WaitForDebugEvent(&ev, INFINITE)) {
            fprintf(stderr, "WaitForDebugEvent failed: %lu\n", GetLastError());
            break;
        }
        if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            DWORD64 image = (DWORD64)(ULONG_PTR)ev.u.CreateProcessInfo.lpBaseOfImage;
            SIZE_T n = 0;
            bp = image + (BREAK_RVA);
            printf("create_process image_base=%llx breakpoint=%llx\n",
                   (unsigned long long)image, (unsigned long long)bp);
            if (ReadProcessMemory(pi.hProcess, (LPCVOID)(ULONG_PTR)bp, &original, 1, &n) && n == 1 &&
                WriteProcessMemory(pi.hProcess, (LPVOID)(ULONG_PTR)bp, &trap, 1, &n) && n == 1) {
                FlushInstructionCache(pi.hProcess, (LPCVOID)(ULONG_PTR)bp, 1);
                installed = 1;
                printf("breakpoint installed, original_opcode=%02x\n", original);
            } else {
                fprintf(stderr, "breakpoint install failed: error=%lu bytes=%llu\n",
                        GetLastError(), (unsigned long long)n);
            }
            if (ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile);
        } else if (ev.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
            if (ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile);
        } else if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            DWORD code = ev.u.Exception.ExceptionRecord.ExceptionCode;
            DWORD64 address = (DWORD64)(ULONG_PTR)ev.u.Exception.ExceptionRecord.ExceptionAddress;
            if (installed && code == EXCEPTION_BREAKPOINT && address == bp) {
                HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, ev.dwThreadId);
                CONTEXT ctx;
                unsigned char out[32], expected[32];
                SIZE_T got1 = 0, got2 = 0, n = 0;
                ZeroMemory(&ctx, sizeof(ctx));
                ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
                if (!thread || !GetThreadContext(thread, &ctx)) {
                    fprintf(stderr, "GetThreadContext failed: %lu\n", GetLastError());
                } else {
                    printf("break_hit exception_address=%llx RIP=%llx RSP=%llx RAX=%llx RBX=%llx RCX=%llx\n",
                           (unsigned long long)address, (unsigned long long)ctx.Rip,
                           (unsigned long long)ctx.Rsp, (unsigned long long)ctx.Rax,
                           (unsigned long long)ctx.Rbx, (unsigned long long)ctx.Rcx);
                    if (ReadProcessMemory(pi.hProcess, (LPCVOID)(ULONG_PTR)ctx.Rax, out, 32, &got1)) dump32("transformed", out);
                    else fprintf(stderr, "read transformed failed: %lu\n", GetLastError());
                    if (ReadProcessMemory(pi.hProcess, (LPCVOID)(ULONG_PTR)ctx.Rbx, expected, 32, &got2)) dump32("expected", expected);
                    else fprintf(stderr, "read expected failed: %lu\n", GetLastError());
                    printf("read_lengths=%llu,%llu\n", (unsigned long long)got1, (unsigned long long)got2);
                    if (WriteProcessMemory(pi.hProcess, (LPVOID)(ULONG_PTR)bp, &original, 1, &n) && n == 1) {
                        FlushInstructionCache(pi.hProcess, (LPCVOID)(ULONG_PTR)bp, 1);
                        ctx.Rip = bp;
                        if (SetThreadContext(thread, &ctx)) {
                            installed = 0;
                            captured = 1;
                            printf("restored instruction and resuming challenge after capture\n");
                        } else fprintf(stderr, "SetThreadContext failed: %lu\n", GetLastError());
                    } else fprintf(stderr, "restore breakpoint failed: %lu\n", GetLastError());
                }
                if (thread) CloseHandle(thread);
            } else if (code != EXCEPTION_BREAKPOINT && code != EXCEPTION_SINGLE_STEP) {
                printf("other_exception code=%08lx address=%llx\n", code, (unsigned long long)address);
                continueStatus = DBG_EXCEPTION_NOT_HANDLED;
            }
        } else if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            printf("child_exit_code=%lu captured=%d\n", ev.u.ExitProcess.dwExitCode, captured);
            done = 1;
        }
        if (!ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, continueStatus)) {
            fprintf(stderr, "ContinueDebugEvent failed: %lu\n", GetLastError());
            break;
        }
    }
    if (installed) {
        SIZE_T n = 0;
        WriteProcessMemory(pi.hProcess, (LPVOID)(ULONG_PTR)bp, &original, 1, &n);
        FlushInstructionCache(pi.hProcess, (LPCVOID)(ULONG_PTR)bp, 1);
    }
    if (!captured) TerminateProcess(pi.hProcess, 6);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return captured ? 0 : 6;
}
