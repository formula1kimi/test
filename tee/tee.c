#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

int main(int argc, char *argv[])
{
    int fd, fd2;
    int len, slen;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pipe file>\n");
        exit(EXIT_FAILURE);
    }

    fd = open(argv[1], O_RDONLY);
    if (fd == -1) {
        perror("open fd in");
        exit(EXIT_FAILURE);
    }

    do {
        len = tee(fd, STDOUT_FILENO, 600, 0); 
        if (len < 0) {
            if (errno == EAGAIN)
                continue;
            perror("tee");
            exit(EXIT_FAILURE);
        } else
            if (len == 0)
                break;
    } while (1);

    close(fd);
    exit(EXIT_SUCCESS);
}
