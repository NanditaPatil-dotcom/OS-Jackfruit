#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int size_mb = 120;
    if (argc > 1) size_mb = atoi(argv[1]);
    size_t bytes = size_mb * 1024 * 1024;
    printf("Allocating %d MiB...\n", size_mb);
    char *p = malloc(bytes);
    if (!p) {
        printf("malloc failed\n");
        return 1;
    }
    memset(p, 0xAA, bytes);
    printf("Allocated %d MiB. Sleeping for 20 seconds...\n", size_mb);
    sleep(20);
    free(p);
    printf("Released memory. Exiting.\n");
    return 0;
}