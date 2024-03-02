#include <stdio.h>
#include <unistd.h>

int main(int argc, char** argv) {
    if(argc < 3) {
        fprintf(stdout, "%s <path_to_shellcode> <key_byte>\n", argv[0]);
        return 0;
    }
    
    if(access(argv[1], F_OK) != -1) {
        int fc;
        FILE *fp = fopen(argv[1], "r");
        while(1) {
            fc = fgetc(fp);
            if(feof(fp)) {
                break;
            }
            fprintf(stdout, "%c", fc^argv[2][0]);
        }
        return 0;
    } else {
        fprintf(stderr, "%s does not exist\n", argv[1]);
        return 1;
    }
}
