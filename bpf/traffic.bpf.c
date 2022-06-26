// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
//#include "vmlinux.h"
#define __KERNEL__
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define SIZE 4096

char LICENSE[] SEC("license") = "Dual BSD/GPL";

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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct ipv4_conn_t);   
	__type(value, struct ipv4_data_t);
} tcp_table SEC(".maps");

int filter_fd = 0;

SEC("socket")
int filter(struct __sk_buff *skb)
{
	struct bpf_sock  *sock = skb->sk;
	if (sock == NULL) {
		bpf_printk("sock is null");
		return 0;
	}
	struct ipv4_conn_t conn_out = {
		.saddr = sock->src_ip4,
		.sport = sock->src_port,
		.daddr = sock->dst_ip4,
		.dport = sock->dst_port
	};

	struct ipv4_data_t *matched = bpf_map_lookup_elem(&tcp_table, &conn_out);
	if (matched) {
		matched->tx_b += skb->len;
	} else {
		struct ipv4_data_t data = {
			.rx_b = 0,
			.tx_b = 0
		};
		bpf_map_update_elem(&tcp_table, &conn_out, &data, 0);
	}


	return 0;
}
