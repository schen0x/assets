#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    volatile int modified;
    modified = 0;
    volatile char buffer[64];
    buffer[0] = 'A';
    buffer[1] = 'B';
    buffer[2] = 'C';
    printf("%p\n", (void *) buffer);
    return 0;
}

