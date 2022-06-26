// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
//#include "vmlinux.h"
#define __KERNEL__
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define SIZE 4096

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __bpf_htons(x) __builtin_bswap16(x)
#define __bpf_constant_htons(x) ___constant_swab16(x)
#define __bpf_ntohs(x) __builtin_bswap16(x)
#define __bpf_constant_ntohs(x) ___constant_swab16(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __bpf_htons(x) (x)
#define __bpf_constant_htons(x) (x)
#define __bpf_ntohs(x) (x)
#define __bpf_constant_ntohs(x) (x)
#else
#error "Fix your compiler's __BYTE_ORDER__?!"
#endif

#define bpf_htons(x)  (__builtin_constant_p(x) ? __bpf_constant_htons(x) : __bpf_htons(x))
#define bpf_ntohs(x)  (__builtin_constant_p(x) ? __bpf_constant_ntohs(x) : __bpf_ntohs(x))

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct message_t {
	__s32 pid;
	__s32 oldstate;
	__s32 newstate;
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(unsigned int));
    __uint(value_size, sizeof(unsigned int));
} events SEC(".maps");


struct sock_state_event {
	__u64 pad;
	void* skaddr;
	__s32 oldstate;
	__s32 newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u8 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr6[16];
	__u8 daddr6[16];
};

struct net_xmit_event {
	__u64 pad;
	void* skbaddr;
	__u32 len;
	__u32 rc;
	char  name[4];
};

#define member_read(destination, source_struct, source_member)                 \
do{                                                                          \
    bpf_probe_read(                                                            \
    destination,                                                             \
    sizeof(source_struct->source_member),                                    \
    ((char*)source_struct) + offsetof(typeof(*source_struct), source_member) \
    );                                                                         \
} while(0)

/*
SEC("tracepoint/sock/inet_sock_set_state")
int tp_inet_sock_set_state(struct sock_state_event *ctx)
{
	unsigned int pid = bpf_get_current_pid_tgid() >> 32;
	struct message_t m = {};
	m.pid = pid;
	member_read(&m.newstate, ctx, newstate);
	member_read(&m.oldstate, ctx, oldstate);
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &m, sizeof(struct message_t));
	return 0;
}
*/

/*
SEC("tracepoint/net/net_dev_xmit")
int ip_net_dev_xmit(struct net_xmit_event *ctx)
{
	unsigned int pid = bpf_get_current_pid_tgid() >> 32;
	struct message_t m = {};
	m.pid = pid;
	m.oldstate =1;
	m.newstate = 1;

	struct sk_buff * skb = NULL;
	member_read(&skb, ctx, skbaddr);
	if (!skb) {
		bpf_printk("empty sk_buf\n");
		return 0;
	}

	struct sock *_sk = NULL;
	member_read(&_sk, skb, sk);
	if (!_sk) {
		bpf_printk("empty sk\n");
		return 0;
	}

	struct sock_common *_skc = (struct sock_common*)_sk;
	if (!_skc) {
		bpf_printk("empty skc\n");
		return 0;
	}
	member_read(&m.daddr, _skc, skc_daddr);
	member_read(&m.dport, _skc, skc_dport);
	member_read(&m.saddr, _skc, skc_rcv_saddr);
	member_read(&m.sport, _skc, skc_num);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &m, sizeof(struct message_t));
	return 0;
}
*/

SEC("tracepoint/net/net_dev_xmit")
int ip_net_dev_xmit(struct net_xmit_event *ctx) {
	unsigned int pid = bpf_get_current_pid_tgid() >> 32;
	struct message_t m = {};
	m.pid = pid;
	m.oldstate =1;
	m.newstate = 1;

	struct sk_buff * skb = NULL;
	member_read(&skb, ctx, skbaddr);
	if (!skb) {
		bpf_printk("empty sk_buf\n");
		return 0;
	}

	// Compute MAC header address
	char* head;
	__u16 mac_header;

	member_read(&head,       skb, head);
	member_read(&mac_header, skb, mac_header);

	// Ether Type
	char * ethhdr = head + mac_header;
	__u16 h_proto = 0;
	bpf_probe_read(&h_proto, sizeof(h_proto), ethhdr+12);

	// Compute IP Header address

    if (bpf_ntohs(h_proto) != ETH_P_IP) {
		bpf_printk("Not IP packet\n");
		return 0;
	}
    char *ipheader = ethhdr + 14;

	__u8 ver_ihl = 0;
	bpf_probe_read(&ver_ihl, 1, ipheader);
	__u32 ihl = (ver_ihl & 0x0f) * 4;
	__u32 ver = (ver_ihl & 0xf0) >> 4;
	m.newstate = ihl;
	m.oldstate = ver;
	
	bpf_probe_read(&m.saddr, sizeof(m.saddr), ipheader+12);
	bpf_probe_read(&m.daddr, sizeof(m.daddr), ipheader+16);

    char *netheader = ipheader + ihl;
	bpf_probe_read(&m.sport, sizeof(m.sport), netheader);
	bpf_probe_read(&m.dport, sizeof(m.dport), netheader+2);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &m, sizeof(struct message_t));
	return 0;
}