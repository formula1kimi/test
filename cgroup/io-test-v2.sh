#!/bin/bash
echo $$
echo $$ > /sys/fs/cgroup/test/cgroup.procs

fio \
-filename=/dev/sdb  \
-iodepth 1   \
-rw=randwrite \
-ioengine=psync \
-bs=16k \
-size=2G \
-numjobs=5 \
-thread \
-direct=1 \
-runtime=15 \
-group_reporting \
-name=mytest
