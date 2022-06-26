// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>
#include <sys/resource.h>
#include <linux/errno.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <errno.h>

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

int open_raw_sock(const char *name);

struct ipv4_conn_t {
	__u32 saddr;
	__u32 sport;
	__u32 daddr;
	__u32 dport;
} __attribute__((packed));

struct ipv4_data_t {
    __u64 rx_b;
    __u64 tx_b;
} __attribute__((packed));


int main(int argc, char **argv)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	struct bpf_link *links[2];
	struct bpf_program *prog;
	struct bpf_object *obj;
	char filename[256];
	int j = 0;
/*
	int err = 0;
	int opt;
    while ((opt = getopt(argc, argv, "p:")) != -1) {
        switch (opt) {
        case 'p':
			pids[pids_count++] = strtoull(optarg, NULL, 10);
            break;
        default:
		    printf("usage: -p <pid> , -n <fd>\n");
			return 1;
        }
    }
*/

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

	prog = bpf_object__next_program(obj, NULL);
	if (prog) {
		const char *pname = bpf_program__name(prog);
		printf("Loaded program name: %s\n", pname);
	} else {
		fprintf(stderr, "ERROR: no program is loaded\n");
	}
	int prog_fd = bpf_program__fd(prog);

	int tcp_table = bpf_object__find_map_fd_by_name(obj, "tcp_table");
	if (tcp_table < 0) {
		fprintf(stderr, "ERROR: finding tcp_table map in obj file failed\n");
		goto cleanup;
	}

	int sock = open_raw_sock("eth0");
	if (sock < 0) {
		fprintf(stderr, "ERROR: Can not open raw socket\n");
		goto cleanup;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0) {
		printf("setsockopt %s\n", strerror(errno));
		goto cleanup;
	}
	struct ipv4_conn_t prev_key = {};
	struct ipv4_conn_t key = {};
	char srcip_chars[128];
	char dstip_chars[128];
	while (!exiting) {
		if (bpf_map_get_next_key(tcp_table, &prev_key, &key) != 0) {
			sleep(1);
			continue;
		}
		const char * srcip = inet_ntop(AF_INET, &key.saddr, srcip_chars, 128);
		const char * dstip = inet_ntop(AF_INET, &key.daddr, dstip_chars, 128);
		printf("src: %s, dst: %s, tx: %llu\n", srcip, dstip, 0LLU);
    	prev_key = key;
		sleep(1);
		/*
    	res = bpf_map_lookup_elem(fd, &key, &value);
    	if(res < 0) {
        	printf("No value??\n");
    	} else {
        	printf("%lld\n", value);
    	}
		*/
	}

cleanup:
	for (j--; j >= 0; j--)
		bpf_link__destroy(links[j]);
	bpf_object__close(obj);
	close(sock);
	return 0;
}

int open_raw_sock(const char *name) {
    struct sockaddr_ll sll;
    int sock;

    sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (sock < 0) {
            printf("cannot create raw socket\n");
            return -1;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex(name);
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            printf("bind to %s: %s\n", name, strerror(errno));
            close(sock);
            return -1;
    }

    return sock;
}