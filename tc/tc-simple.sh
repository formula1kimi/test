#!/bin/bash
set -x
dev=$1
rate=$2

tc qdisc delete dev $dev root
tc qdisc add dev $dev  root handle 1:0 htb default 1 || exit 0
tc class add dev $dev  parent 1:0 classid 1:1  htb rate ${rate}mbit burst 65535 cburst 65535 || exit 0

