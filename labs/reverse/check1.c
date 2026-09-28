#include <stdio.h>
#include <string.h>

/* Exercise R1: find an input accepted by the program. */
static const unsigned char expected[] = {
    0x45, 0x4f, 0x42, 0x44, 0x58, 0x51, 0x46, 0x55, 0x46, 0x51,
    0x50, 0x46, 0x7c, 0x5b, 0x4c, 0x51, 0x5e
};

int main(void) {
    char input[128];
    if (!fgets(input, sizeof input, stdin)) return 1;
    input[strcspn(input, "\n")] = '\0';
    if (strlen(input) != sizeof expected) {
        puts("nope");
        return 1;
    }
    for (size_t i = 0; i < sizeof expected; i++) {
        if (((unsigned char)input[i] ^ 0x23) != expected[i]) {
            puts("nope");
            return 1;
        }
    }
    puts("correct");
    return 0;
}
