#include <stddef.h>
#include <stdio.h>
struct Session { char name[24]; void (*next)(void); };
int main(void) {
    printf("sizeof(struct Session) = %zu\n", sizeof(struct Session));
    printf("offsetof(next)         = %zu\n", offsetof(struct Session, next));
    return 0;
}
