// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>
#include <sys/resource.h>
#include <linux/errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>


#define SIZE 4096
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

struct message_t {
	unsigned int len;
    char data[SIZE];
};

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	struct message_t msg;
	memcpy(&msg, data, sizeof(struct message_t));
	if (msg.len >= SIZE) {
		msg.data[SIZE-1] = 0;
	} else {
		msg.data[msg.len] = 0;
	}
	printf("write data size: %d\n", msg.len);
	printf("%s\n", msg.data);
	printf("-----------------------------\n");
}

int main(int argc, char **argv)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	struct bpf_link *links[2];
	struct bpf_program *prog;
	struct bpf_object *obj;
	char filename[256];
	int j = 0;
	int err = 0;

	int opt;
	uint64_t pids[256]={0};
	uint32_t pids_count=0;
	int fds[256]={0};
	uint32_t fds_count=0;
    while ((opt = getopt(argc, argv, "p:f:")) != -1) {
        switch (opt) {
        case 'p':
			pids[pids_count++] = strtoull(optarg, NULL, 10);
            break;
        case 'f':
            fds[fds_count++] = atoi(optarg);
            break;
        default:
		    printf("usage: -p <pid> , -n <fd>\n");
			return 1;
        }
    }

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK)");
		return 1;
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);


	snprintf(filename, sizeof(filename), "%s.bpf.o", argv[0]);
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 0;
	}

	/* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}


	int pid_map = bpf_object__find_map_fd_by_name(obj, "pid_table");
	if (pid_map < 0) {
		fprintf(stderr, "ERROR: finding pid_table map in obj file failed\n");
		goto cleanup;
	}
	int fd_map = bpf_object__find_map_fd_by_name(obj, "fd_table");
	if (fd_map < 0) {
		fprintf(stderr, "ERROR: finding fd_table map in obj file failed\n");
		goto cleanup;
	}

	// Update table.
	for (int i = 0; i < pids_count; i++) {
		printf("pid: %lu\n", pids[i]);
		int set = 1;
		if (bpf_map_update_elem(pid_map, &pids[i], &set, 0) != 0) {
			fprintf(stderr, "ERROR: update pid_map failed\n");
			goto cleanup;
		}
	}
	for (int i = 0; i < fds_count; i++) {
		printf("fd: %d\n", fds[i]);
		int set = 1;
		if (bpf_map_update_elem(fd_map, &fds[i], &set, 0) != 0) {
			fprintf(stderr, "ERROR: update fd_map failed\n");
			goto cleanup;
		}
	}


	bpf_object__for_each_program(prog, obj) {
		links[j] = bpf_program__attach(prog);
		if (libbpf_get_error(links[j])) {
			fprintf(stderr, "ERROR: bpf_program__attach failed\n");
			links[j] = NULL;
			goto cleanup;
		}
		j++;
	}

	int event_map = bpf_object__find_map_fd_by_name(obj, "events");
	if (event_map < 0) {
		fprintf(stderr, "ERROR: finding events map in obj file failed\n");
		goto cleanup;
	}

	struct perf_buffer *pb = NULL;
	pb = perf_buffer__new(event_map, 8 /* 32KB per CPU */, handle_event, NULL, NULL, NULL);
	if (libbpf_get_error(pb)) {
		err = -1;
		fprintf(stderr, "Failed to create perf buffer\n");
		goto cleanup;
	}

	printf("Successfully started!\n");
	/* Process events */
	while (!exiting) {
		err = perf_buffer__poll(pb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	for (j--; j >= 0; j--)
		bpf_link__destroy(links[j]);

	bpf_object__close(obj);
	return 0;
}
