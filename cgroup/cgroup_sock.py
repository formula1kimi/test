#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF, BPFAttachType
import os


text = """
#include <linux/bpf.h>
#include <linux/socket.h>

int test_cgroup_sock(struct bpf_sock *sock)
{
    int r = 0;
    char eth[] = "eth0";
    bpf_trace_printk("bpf_sock.protocol = %d\\n", sock->protocol); 
    /* unfortunately, CGROUP_SOCK don't support the setsockopt.
    r = bpf_setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, eth, sizeof(eth));
    if (r != 0) {
        bpf_trace_printk("failed to bind socket to device\\n"); 
    }
    */
    return 1; //return 1 as permit, 0 as deny.
}
"""
fn = None
fd = None
bpf = None

btype = BPF.CGROUP_SOCK
atype = BPFAttachType.CGROUP_INET_SOCK_CREATE

try:
    bpf = BPF(text=text)
    fn = bpf.load_func("test_cgroup_sock", btype)
    fd = os.open("/sys/fs/cgroup/test", os.O_RDONLY)
    bpf.attach_func(fn, fd, atype)
    bpf.trace_print()
finally:
    print("%s, %s, %s" % (bpf, fn, fd))
    if bpf is not None and fn is not None and fd is not None:
        print("Release bpf")
        bpf.detach_func(fn, fd, atype)

print("OK")
