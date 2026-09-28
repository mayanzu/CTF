#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>
static int logfd = -1;
static long (*real_ptrace_fn)(enum __ptrace_request, ...);
__attribute__((constructor)) static void setup(void) {
    const char *path = getenv("TRACE_LOG");
    real_ptrace_fn = dlsym(RTLD_NEXT, "ptrace");
    if (path) logfd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
}
long ptrace(enum __ptrace_request request, ...) {
    va_list ap; va_start(ap, request);
    pid_t pid = va_arg(ap, pid_t);
    void *addr = va_arg(ap, void *);
    void *data = va_arg(ap, void *);
    va_end(ap);
    long result = real_ptrace_fn(request, pid, addr, data);
    int saved_errno = errno;
    if (logfd >= 0) {
        if (request == PTRACE_GETREGS || request == PTRACE_SETREGS) {
            struct user_regs_struct *r = (struct user_regs_struct *)data;
            dprintf(logfd, "%s pid=%d result=%ld rip=%llx rsp=%llx rax=%llx rbx=%llx rcx=%llx rdx=%llx rsi=%llx rdi=%llx eflags=%llx\n",
                request == PTRACE_GETREGS ? "GETREGS" : "SETREGS", pid, result,
                (unsigned long long)r->rip, (unsigned long long)r->rsp,
                (unsigned long long)r->rax, (unsigned long long)r->rbx,
                (unsigned long long)r->rcx, (unsigned long long)r->rdx,
                (unsigned long long)r->rsi, (unsigned long long)r->rdi,
                (unsigned long long)r->eflags);
        } else if (request == PTRACE_CONT || request == PTRACE_TRACEME || request == PTRACE_KILL) {
            dprintf(logfd, "REQ=%d pid=%d addr=%p data=%p result=%ld errno=%d\n", request, pid, addr, data, result, saved_errno);
        } else if (request == PTRACE_POKETEXT || request == PTRACE_POKEDATA) {
            dprintf(logfd, "POKE req=%d pid=%d addr=%p data=%p result=%ld errno=%d\n", request, pid, addr, data, result, saved_errno);
        }
    }
    errno = saved_errno;
    return result;
}
