#!/bin/bash
cgexec -g blkio:/test  fio \
-filename=/dev/sdb  \
-direct 0 \
-iodepth 1   \
-rw=write \
-ioengine=psync \
-bs=16k \
-size=2G \
-numjobs=5 \
-thread \
-runtime=10 \
-group_reporting \
-name=mytest
