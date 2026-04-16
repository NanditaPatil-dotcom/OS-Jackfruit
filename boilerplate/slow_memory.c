#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main() {
    int total = 120; // MB
    int step = 5;    // MB per second
    char *p = NULL;
    for (int i = step; i <= total; i += step) {
        p = realloc(p, i * 1024 * 1024);
        if (!p) { printf("realloc failed\n"); return 1; }
        memset(p + (i-step)*1024*1024, 0xAA, step*1024*1024);
        printf("Allocated %d MB\n", i);
        sleep(1);
    }
    sleep(5);
    free(p);
    return 0;
}