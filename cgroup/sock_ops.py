#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF, BPFAttachType
import os


text = """
#include <linux/bpf.h>
#include <linux/socket.h>

int test_sock_ops(struct bpf_sock_ops *skops)
{
    int r = 0;
    int op = (int) skops->op;
    char eth[] = "eth0";
    bpf_trace_printk("skops->op = %d\\n", op); 
    /*
    if (op == BPF_SOCK_OPS_TCP_LISTEN_CB || op == BPF_SOCK_OPS_TCP_CONNECT_CB) {
        r = bpf_setsockopt(skops, SOL_SOCKET, SO_BINDTODEVICE, eth, sizeof(eth));
        if (r != 0) {
            bpf_trace_printk("failed to bind socket to device\\n"); 
        }
    }
    */
    return 0;
}

"""
fn = None
fd = None
bpf = None

btype = BPF.SOCK_OPS
atype = BPFAttachType.CGROUP_SOCK_OPS

try:
    bpf = BPF(text=text)
    fn = bpf.load_func("test_sock_ops", btype)
    fd = os.open("/sys/fs/cgroup/test", os.O_RDONLY)
    bpf.attach_func(fn, fd, atype)
    bpf.trace_print()
finally:
    print("%s, %s, %s" % (bpf, fn, fd))
    if bpf is not None and fn is not None and fd is not None:
        print("Release bpf")
        bpf.detach_func(fn, fd, atype)

print("OK")
