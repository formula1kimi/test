#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF, BPFAttachType
import os


text = """
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/udp.h>

int test_cgroup_skb(struct __sk_buff *s)
{
    int r = 0;
    uint64_t cgid = bpf_skb_cgroup_id(s);

    unsigned char* data_start = (unsigned char *)(unsigned long long)s->data;
    unsigned char* data_end = (unsigned char *)(unsigned long long)s->data_end;

    if (data_start + 20 > data_end) {
        bpf_trace_printk("IP header Error\\n");
        return 1;
    }
    bpf_trace_printk("protocol=%u, dst=0x%x, cgid=%llu\\n",data_start[9], s->remote_ip4, cgid); 
    return 1;
}

"""
fn = None
fd = None
bpf = None

btype = BPF.CGROUP_SKB
atype = BPFAttachType.CGROUP_INET_EGRESS

try:
    bpf = BPF(text=text)
    fn = bpf.load_func("test_cgroup_skb", btype)
    fd = os.open("/sys/fs/cgroup/test", os.O_RDONLY)
    bpf.attach_func(fn, fd, atype)
    bpf.trace_print()
finally:
    print("%s, %s, %s" % (bpf, fn, fd))
    if bpf is not None and fn is not None and fd is not None:
        print("Release bpf")
        bpf.detach_func(fn, fd, atype)

print("OK")
