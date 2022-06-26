#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define KB (1024)
#define MB (1024 * KB)
#define GB (1024 * MB)
int total = 0;

int main(int argc, char *argv[])
{
    char *p;
again:
    /*
	while ((p = (char *)malloc(GB)))
		memset(p, 0, GB);
    */
    while ((p = (char *)malloc(MB))) {
        total += 1;
        printf("%dMB\n", total);
        usleep(5000);
        memset(p, total, MB);
    }
    if (p == NULL) {
        printf("Can not allocte more memory 1.\n");
    }

    while ((p = (char *)malloc(KB)))
	memset(p, 0, KB);
    if (p == NULL) {
        printf("Can not allocte more memory 2.\n");
    }
    goto again;
    return 0;
}
