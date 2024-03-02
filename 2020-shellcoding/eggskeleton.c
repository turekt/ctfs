#include <stdio.h>
#include <string.h>

unsigned char eggg[] = "EGGHUNTER";
unsigned char code[] = "egggeggg" "SHELLCODE";

int main() {
    printf("Egghunter length: %ld\n", strlen(eggg));
    printf("Shellcode length: %ld\n", strlen(code));
    void (*ret)() = (void *)eggg;
    ret();
    return 0;
}
