#include <stdio.h>
#include <unistd.h>

/* Exercise P1: a small, deliberate control-flow overwrite. Build in WSL. */
static void normal(void) { puts("Try again."); }
void win(void) { puts("flag{control_flow_redirected}"); }

struct Session {
    char name[24];
    void (*next)(void);
};

int main(void) {
    struct Session session = {{0}, normal};
    puts("Name:");
    fflush(stdout);
    /* Deliberately writes past name into the adjacent function pointer. */
    if (read(STDIN_FILENO, session.name, sizeof session) < 0) return 1;
    session.next();
    return 0;
}
