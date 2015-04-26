#include <stdio.h>

static void _libinit() __attribute__((constructor));

void _libinit() {
    printf("[+] lib init\n");
}
