set -x
tc qdisc delete dev eth1 root
tc qdisc add dev eth1 root handle 1:0 htb default 10
tc class add dev eth1 parent 1:0 classid 1:1  htb rate 1000mbit  cburst 16k burst 16k
tc class add dev eth1 parent 1:1 classid 1:10 htb rate 200mbit prio 100 cburst 16k burst 16k
tc class add dev eth1 parent 1:1 classid 1:11 htb rate 200mbit ceil 300mbit prio 100 cburst 16k burst 16k
tc class add dev eth1 parent 1:1 classid 1:12 htb rate 600mbit ceil 1000mbit prio 100 cburst 16k burst 16k
tc class add dev eth1 parent 1:12 classid 1:20 htb rate 200mbit ceil 1000mbit prio 100 cburst 16k burst 16k
tc class add dev eth1 parent 1:12 classid 1:21 htb rate 400mbit ceil 1000mbit prio 100 cburst 16k burst 16k

#tc filter add dev eth1 protocol ip parent 1:0 prio 10 u32 \
#match udp dst 5001 ffff classid 1:20

# tc filter add dev eth1 protocol ip parent 1:0 prio 10 u32 \
#  match ip protocol 0x6 0xff \
#  match ip dport 5001 0xffff \
#  flowid 1:20
#tc filter add dev eth1 protocol ip parent 1:0 prio 10 u32 \
#match ip protocol 17 0xff flowid 1:21
#tc filter add dev eth1 parent 1: protocol ip prio 1 handle 111:  cgroup

#tc filter add dev eth1 parent 1:0 protocol ip prio 5  handle 1: u32 divisor 1
#tc filter add dev eth1 parent 1:0 protocol ip prio 5  u32 ht 1: match tcp dst 5001 0xFFFF match ip protocol 6 0xFF  flowid 1:20
#tc filter add dev eth1 parent 1:0 protocol ip prio 5 u32 ht 800:: match u8 0 0 offset at 0 mask 0x0f00 shift 6 link 1:

tc filter add dev eth1 parent 1:0 protocol ip prio 5  handle 1: u32 divisor 32
tc filter add dev eth1 parent 1:0 protocol ip prio 5  u32 ht 1: match tcp dst 5001 0xFFFF flowid 1:20

tc filter add dev eth1 parent 1:0 protocol ip prio 5  handle 2: u32 divisor 32
tc filter add dev eth1 parent 1:0 protocol ip prio 5  u32 ht 2: match udp dst 5001 0xFFFF flowid 1:21

tc filter add dev eth1 parent 1:0 protocol ip prio 5 u32 ht 800:: match ip protocol 6 0xff  link 1: offset at 0 mask 0x0f00 shift 6 
tc filter add dev eth1 parent 1:0 protocol ip prio 5 u32 ht 800:: match ip protocol 17 0xff  link 2: offset at 0 mask 0x0f00 shift 6 
