#!/bin/bash
FILE=/sys/fs/cgroup/cpu/t/cpuacct.usage
while [ 1 ]; do
    x1=$(cat $FILE); sleep 1; x2=$(cat $FILE); echo "($x2-$x1)*100/1000000000" | bc;
done
