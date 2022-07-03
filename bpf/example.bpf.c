// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */

/*
 * This example demo how to use kprobe to watch the write syscall
 * log the writing data filtered by pid and fd.
 */

#define __KERNEL__

// This is kernel's bpf include file, contains bpf syscall and helper function for userspace program.
#include <linux/bpf.h>
// This is libbpf's include files, under libbpf's include folder.
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define SIZE 4096

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct pt_regs {
	long unsigned int r15;
	long unsigned int r14;
	long unsigned int r13;
	long unsigned int r12;
	long unsigned int bp;
	long unsigned int bx;
	long unsigned int r11;
	long unsigned int r10;
	long unsigned int r9;
	long unsigned int r8;
	long unsigned int ax;
	long unsigned int cx;
	long unsigned int dx;
	long unsigned int si;
	long unsigned int di;
	long unsigned int orig_ax;
	long unsigned int ip;
	long unsigned int cs;
	long unsigned int flags;
	long unsigned int sp;
	long unsigned int ss;
};

struct message_t {
	unsigned int len;
    char data[SIZE];
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, unsigned int);   
	__type(value, struct message_t);
} msg_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, unsigned int);   
	__type(value, unsigned int);
} pid_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, int);   
	__type(value, unsigned int);
} fd_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(unsigned int));
    __uint(value_size, sizeof(unsigned int));
} events SEC(".maps");

int filter_fd = 0;

SEC("kprobe/ksys_write")
int ksys_write(struct pt_regs *ctx)
{
	int fd = (int)PT_REGS_PARM1(ctx); 
	void *buf = (void*)PT_REGS_PARM2(ctx);
	unsigned long count = (unsigned long)PT_REGS_PARM3(ctx);

	unsigned int pid = bpf_get_current_pid_tgid() >> 32;
    char prog[32] = {0};
	bpf_get_current_comm(prog, 32);
	unsigned int *matched = bpf_map_lookup_elem(&pid_table, &pid);
	if (matched == NULL) {
		return 0;
	}
	if (filter_fd != 0) {
		matched = bpf_map_lookup_elem(&fd_table, &fd);
		if (matched == NULL) {
			return 0;
		}
	}
	/* by name filter
	bpf_printk("prog: %s", prog);
	bpf_printk("sizeof(target): %d", sizeof(target));
	bool match = true;
	for (int i = 0; i < sizeof(target) && i < 32; i++) {
		if (prog[i] == 0 || target[i] == 0)
			break;
		if (prog[i] != target[i]) {
			match = false;
			break;
		}
	}
	if (!match) return 0;
	*/

	//bpf_printk("prog: %s(%d), write data size:%ld", prog, pid, count);
	unsigned int key = 0;
	struct message_t* msg = bpf_map_lookup_elem(&msg_table, &key);
    if (!msg)
        return 0;
	msg->len = count;
	msg->data[0]=0;
	int s = count > SIZE ? SIZE : count;
	long r = bpf_probe_read_user(msg->data, s, buf);
	if (r < 0) {
		msg->data[0]='?';
	} 
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, msg, sizeof(struct message_t));
	
	//bpf_printk("write data: %s\n", msg->data);
	return 0;
}
