# 2022 TBTL - Lucky

Lucky was a simple pwn challenge. To get the flag a simple buffer overflow must be leveraged to change the value of the integer, located on the stack alongside the user attempts, and point the unknown password to compare to itself.

We got the code:
```c
// gcc -fno-stack-protector -o lucky lucky.c

#include <stdio.h>
#include <string.h>

void print_flag() {
  FILE* in;
  char flag[64];
  
  in = fopen("flag.txt", "rt");
  fscanf(in, "%s", flag);
  fclose(in);
  printf("%s\n", flag);
}

void login() {
  int i;
  char attempt[3][16];
  char admin_pass[16];

  FILE *in;
  in = fopen("admin.txt", "rt");
  fscanf(in, "%s", admin_pass);
  fclose(in);
  
  for (i=0; i<3; i++) {
    printf("Enter admin password, attempt %d: ", i+1);
    scanf("%s", attempt[i]);
    if (!strcmp(attempt[i], admin_pass)) {
      print_flag();
      return ;
    }
  }
  printf("Login failed.\n");
}

int main() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  login();
  return 0;
}
```

From the code it is immediately obvious that you can overflow only into `int i` due to the way the stack is expanded and filled. In assembly it is much more clear that the `i` value is used to reference the `attempt` currently being used:
```
   0x1310 <login+141>:	call   0x1130 <__isoc99_scanf@plt>
   0x1315 <login+146>:	lea    rax,[rbp-0x40]
   0x1319 <login+150>:	mov    edx,DWORD PTR [rbp-0x4]	; `i` referenced here
   0x131c <login+153>:	movsxd rdx,edx
   0x131f <login+156>:	shl    rdx,0x4
   0x1323 <login+160>:	add    rdx,rax
   0x1326 <login+163>:	lea    rax,[rbp-0x50]
   0x132a <login+167>:	mov    rsi,rax
   0x132d <login+170>:	mov    rdi,rdx			; position loaded here as arg
   0x1330 <login+173>:	call   0x1110 <strcmp@plt>
```

The idea is pretty simple: on your first attempt overflow the buffer into `int i` and set the `int i` value to -1 (0xffffffff). This causes the position to "wrap around" (or "go backwards") and the `admin_pass` is loaded into `strcmp` as both first and second argument causing the `strcmp` check to succeed and print us the flag.
```
$ python3 solve_2022_tbtl_lucky.py 
[+] Opening connection to 0.cloud.chals.io on port 15426: Done
[*] Switching to interactive mode
TBTL{P01n7er_i5_ju57_n0t_Sm4r7}
[*] Got EOF while reading in interactive
```

Solution code is in `solve_2022_tbtl_lucky.py`
