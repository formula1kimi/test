#!/bin/bash
ip route flush table 1000
ip route flush table 2000

ip route add default via 172.28.192.1 dev eth2 table 1000
ip route add to 172.28.192.0/20 dev eth2 table 1000

ip route add default via 172.28.192.1 dev eth3 table 2000
ip route add to 172.28.192.0/20 dev eth3 table 2000

echo 1000
ip route show table 1000
echo 2000
ip route show table 2000
echo rules
ip rule show
