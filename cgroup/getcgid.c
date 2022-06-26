#define _GNU_SOURCE 
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

/**
 * get_cgroup_id() - Get cgroup id for a particular cgroup path
 * @path: The cgroup path, relative to the workdir, to join
 *
 * On success, it returns the cgroup id. On failure it returns 0,
 * which is an invalid cgroup id.
 * If there is a failure, it prints the error to stderr.
 */
unsigned long long get_cgroup_id(const char *path)
{
        int dirfd, err=-1, flags, mount_id, fhsize;
        union {
                unsigned long long cgid;
                unsigned char raw_bytes[8];
        } id;
        struct file_handle *fhp, *fhp2;
        unsigned long long ret = 0;

        dirfd = AT_FDCWD;
        flags = 0;
        fhsize = sizeof(*fhp);
        fhp = calloc(1, fhsize);
        if (!fhp) {
                perror("calloc");
                return err;
        }
        err = name_to_handle_at(dirfd, path, fhp, &mount_id, flags);
        if (err >= 0 || fhp->handle_bytes != 8) {
                printf("name_to_handle_at, err = %s(%d)\n", strerror(errno), errno);
                printf("returned handle bytes = %d\n", fhp->handle_bytes);
                goto free_mem;
        }

        //printf("returned handle bytes = %d\n", fhp->handle_bytes);
        fhsize = sizeof(struct file_handle) + fhp->handle_bytes;
        fhp2 = realloc(fhp, fhsize);
        if (!fhp2) {
                perror("realloc");
                goto free_mem;
        }
        err = name_to_handle_at(dirfd, path, fhp2, &mount_id, flags);
        fhp = fhp2;
        if (err < 0) {
                perror("name_to_handle_at");
                goto free_mem;
        }

        memcpy(id.raw_bytes, fhp->f_handle, 8);
        ret = id.cgid;

free_mem:
        free(fhp);
        return ret;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Require cgroup path\n");
        return 0;
    }
    unsigned long long cgid = get_cgroup_id(argv[1]);
    printf("%llu\n", cgid);
    printf("0x%llx\n", cgid);
    return 0;
}
