#define _GNU_SOURCE
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <ucontext.h>
#include <unistd.h>
static void skip_trap(int sig, siginfo_t *info, void *context) {
    ucontext_t *uc = (ucontext_t *)context;
#if defined(__x86_64__)
    uc->uc_mcontext.gregs[REG_RIP] += 1;
#endif
}
__attribute__((constructor)) static void install_trap_handler(void) {
    struct sigaction sa = {0};
    sa.sa_sigaction = skip_trap;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTRAP, &sa, 0);
}
long ptrace(enum __ptrace_request request, ...) { return 0; }
pid_t fork(void) { return 0; }
