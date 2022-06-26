#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <linux/if_pppox.h>
#include <linux/ppp_defs.h>
#include <linux/pkt_cls.h>
#include <linux/swab.h>
// #include <netinet/ppp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <arpa/inet.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_sched.h>

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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, int);   
	__type(value, int);
} tcp_sport_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, int);   
	__type(value, int);
} udp_sport_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, int);   
	__type(value, int);
} tcp_dport_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, int);   
	__type(value, int);
} udp_dport_map SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, int);   
	__type(value, int);
} net_cls_map SEC(".maps");

SEC("tc") int cls_main(struct __sk_buff *skb)
{
    int *value, classid=0;

    // If we found the skb's cgroup cls_net classid mapped in net_cls_map, directly use it.
    uint32_t cg_classid = bpf_get_cgroup_classid(skb);
    if (cg_classid != 0) {
        value = bpf_map_lookup_elem(&net_cls_map, &cg_classid);
        if (value) {
            classid = *value;
            bpf_printk("cgroup classid = %u(0x%x)\n", cg_classid, cg_classid);
            return classid;
        }
    }

    void* data_start = (void *)(unsigned long long)skb->data;
    void* data_end = (void *)(unsigned long long)skb->data_end;

    struct ethhdr *pethhdr = (struct ethhdr *)data_start;

    if ((void *)pethhdr + sizeof(struct ethhdr) > data_end) {
        return 0;
    }

    // from linux/if_ether.h
    // ETH_P_IP       0x0800 Internet Protocol packet
    // ETH_P_IPV6     0x86DD IPv6 over bluebook
    // ETH_P_PPP_DISC 0x8863 PPPoE discovery messages
    // ETH_P_PPP_SES  0x8864 PPPoE session messages

    // https://www.rfc-editor.org/rfc/rfc2516.txt

    struct iphdr *piphdr = (struct iphdr *)0;
    switch (bpf_ntohs(pethhdr->h_proto)) {
    case ETH_P_IP: {
        piphdr = (struct iphdr *)((char *)pethhdr + sizeof(struct ethhdr));
        break;
    }
    case ETH_P_PPP_SES: {
        struct pppoe_hdr* p_pppoe = (struct pppoe_hdr*)((char *)pethhdr + sizeof(struct ethhdr));
        if ((void *)p_pppoe + sizeof(struct pppoe_hdr) + 2 > data_end) {
            return 0;
        }
        unsigned int ppp_proto = bpf_ntohs(*(unsigned short *)((char *)p_pppoe + sizeof(struct pppoe_hdr)));
        switch (ppp_proto) {
        case PPP_IP: {
            piphdr = (struct iphdr *)((char *)p_pppoe + sizeof(struct pppoe_hdr) + 2);
            bpf_printk("IP packet in PPPoE\n");
            break;
        }
        default:
            bpf_printk("Unknown ppp proto: %d\n", ppp_proto);
        }
        break;
    }
    }

    if (piphdr == NULL) {
        bpf_printk("IP header is NULL\n");
        return 0;
    } 


    if ((void *)piphdr + 20 > data_end) {
        bpf_printk("IP header length is not complete\n");
        return 0;
    }
    if ((void *)piphdr + 4 * piphdr->ihl > data_end) {
        bpf_printk("IP header length is not complete 2\n");
        return 0;
    }

    /*
    unsigned int ipversion = (*(unsigned char*)piphdr & 0xF0) >> 4;
    bpf_printk("IP Version = %u\n", ipversion);
    bpf_printk("IP Version = %u\n", piphdr->version);
    bpf_printk("IP Header Size = %u\n", piphdr->ihl * 4);
    bpf_printk("IP Src = %x\n", piphdr->saddr);
    bpf_printk("IP Dst = %x\n", piphdr->daddr);
    unsigned char* b = (unsigned char*)piphdr;
    for (int i = 0; i < 10; i++) {
        bpf_printk("%x %x\n", b[2*i], b[2*i+1]);
    }
    */


    if (piphdr->protocol != IPPROTO_TCP && piphdr->protocol != IPPROTO_UDP) {
        bpf_printk("Not interested IP protocol: %d\n", piphdr->protocol);
        return 0;
    }

    unsigned int sport = 0;
    unsigned int dport = 0;
    if (piphdr->protocol == IPPROTO_TCP) {
        struct tcphdr *ptcphdr = (struct tcphdr *)((void *)piphdr + 4 * piphdr->ihl);
        if ((void*)ptcphdr + 16 > data_end) {
            bpf_printk("TCP header is not complete\n");
            return 0;
        }
        sport = bpf_ntohs(ptcphdr->source);
        dport = bpf_ntohs(ptcphdr->dest);
        value = bpf_map_lookup_elem(&tcp_sport_map, &sport);
        if (value) {
            classid = *value;
            bpf_printk("tcp sport %u ---> class 0x%x\n", sport, classid);
        } else {
            value = bpf_map_lookup_elem(&tcp_dport_map, &dport);
            if (value) {
                classid = *value;
                bpf_printk("tcp dport %u ---> class 0x%x\n", dport, classid);
            }
            else {
                //Nothing port matched.
                bpf_printk("TCP port is not matched sport=%d, dport=%d\n",sport,dport);
                return 0;
            }
        }
    } 
    else if (piphdr->protocol == IPPROTO_UDP) {
        struct udphdr *pudphdr = (struct udphdr *)((char *)piphdr + 4 * piphdr->ihl);
        if ((void*)pudphdr + 8 > data_end) {
            bpf_printk("UDP header is not complete\n");
            return 0;
        }
        sport = bpf_ntohs(pudphdr->source);
        dport = bpf_ntohs(pudphdr->dest);
        value = bpf_map_lookup_elem(&udp_sport_map, &sport);
        if (value) {
            classid = *value;
            bpf_printk("udp sport %u ---> class 0x%x\n", sport, classid);
        } else {
            value = bpf_map_lookup_elem(&udp_dport_map, &dport);
            if (value) {
                classid = *value;
                bpf_printk("udp dport %u ---> class 0x%x\n", dport, classid);
            }
            else {
                //Nothing port matched.
                bpf_printk("UDP port is not matched sport=%d, dport=%d\n",sport,dport);
                return 0;
            }
        }   
    }

    return classid;
}

char __license[] SEC("license") = "GPL";

