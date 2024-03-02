#include <stdio.h>
#include <string.h>

unsigned char code[] = "SHELLCODE";

int main() {
    printf("Shellcode length: %ld\n", strlen(code));
    void (*ret)() = (void *)code;
    ret();
    return 0;
}
