#/bin/bash

# eth0是物理接口, 测试环境 Centos 7 5.4.96-200.el7.x86_64

# app --> veth0(10.10.50.2) --> (veth1)@br0(10.10.50.1) --> eth0(172.17.48.103) --> (114.114.114.114)

# 1. 通过添加的第二个default网关路由，告知从veth0访问外部，需要走br0网关。
# 2. veth0到br0的时候，SNAT到10.10.50.3地址
# 3. br0到eth0时，再次SNAT到外部网卡eth0地址（MASQUERADE）
# 4. 回包从eth0接收到，SRC恢复到源地址为10.10.50.3，不是本地IP，所以继续转发到br0
# 5. br0收到回包后，不是本地IP，查询10.10.50.3的MAC地址为veth0（预先添加ARP记录），继续转发到veth0
# 6. veth0收到回包后，恢复到10.10.50.2的源地址，是本地地址，发给本地程序。

# 为什么要不直接使用10.10.50.2，而是要SNAT？
# 发出的第一个报文10.10.50.2-->External 会被conntrack记录。
# 如果第2步不SNAT到其他IP，只路由，当最后从eth0发出去时，还需要进入nat表做MASQ，只有New状态的flow才会进去，但是这个报文已经在conntrack中，不会进入nat表。

# 为什么用10.10.50.3？为什么不用10.10.50.1？
# 10.10.50.1是本地IP，如果用SNAT到它，当eth0收报回包后，SRC恢复成10.10.50.1，本地地址不再路由，直接接收给本地了。

ip l a veth0 type veth peer name veth1
ip l a br0 type bridge
ip l s veth1 master br0
ip a a 10.10.50.1/24 dev br0
ip a a 10.10.50.2/24 dev veth0
ip l s veth0 up
ip l s veth1 up
ip l s br0 up
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 1 > /proc/sys/net/ipv4/conf/all/accept_local

# 通过veth0访问外网的时候，走10.10.50.3这个网关，作为下一跳
ip route add default via 10.10.50.1 dev veth0 metric 500
# 10.10.50.0的报文走br0
ip route add 10.10.50.0/24 dev br0  metric 100
# 更新自动添加的veth0上的路由的metric，优先br0
ip route del 10.10.50.0/24 dev veth0 src 10.10.50.2
ip route add 10.10.50.0/24 dev veth0 src 10.10.50.2 metric 200

# 允许br0和eth0间的报文转发
iptables -w -t filter -A FORWARD -i br0 -o eth0 -j ACCEPT
iptables -w -t filter -A FORWARD -i eth0 -o br0 -j ACCEPT
# 当从veth0发送报文时，做SNAT到10.10.50.3
iptables -w -t nat -A POSTROUTING -o veth0 -j SNAT --to-source 10.10.50.3
# 当从br0出来的报文转发到eth0时，做MASQUERADE
iptables -w -t nat -A POSTROUTING -s 10.10.50.3/32 -o eth0 -j MASQUERADE

# 告诉br0，10.10.50.3的MAC地址为veth0（10.10.50.3没有对应实际接口，ARP无法找到它）
MAC=$(ip -br link show dev veth0 | awk '{print $3}')
ip neigh add 10.10.50.3 lladdr ${MAC} dev br0  nud permanent
sleep 1
ping -I veth0 114.114.114.114 -c 10
# 添加chain上的log，方便跟踪
# iptables -w -t mangle -A POSTROUTING -p icmp -j LOG --log-prefix "POSTROUTING(mangle): "
# iptables -w -t nat -I POSTROUTING -p icmp -j LOG --log-prefix "POSTROUTING(nat): "
# iptables -w -t mangle -A PREROUTING -p icmp -j LOG --log-prefix "PREROUTING(mangle): "
# iptables -w -t mangle -A INPUT -p icmp -j LOG --log-prefix "INPUT(mangle): "
# iptables -w -t mangle -A FORWARD -p icmp -j LOG --log-prefix "FORWARD(mangle): "


