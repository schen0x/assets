#include <stdlib.h>
#include <string.h>

int main(int argc, char const *argv[])
{
    volatile char buffer[64];
    volatile char src[10] = "ABC";
    strcpy(buffer, src);
    return 0;
}