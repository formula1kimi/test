function mirror_device() {
    local DEVICE MACADDR IPADDR NAME 
    DEVICE=$1
    NAME=$2
    GW=$3
    IPADDR=$(ip -4 addr show dev $DEVICE | grep inet | awk '{print $2}')
    MACADDR=$(ip link show dev $DEVICE | grep link | awk '{print $2}')

    docker rm -f ${DEVICE}-${NAME}
    docker run -d --privileged --name ${DEVICE}-${NAME} --sysctl net.ipv4.ip_local_port_range="8192 $((8192 + 8192 - 1))" --network none ubuntu:20.04 tail -f /dev/null
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    NETNS=$(docker inspect --format "{{.State.Pid}}" ${DEVICE}-${NAME})
    
    ip link add veth-${DEVICE}-${NAME} type veth peer name $DEVICE netns $NETNS
    
    nsenter -t $NETNS -n ip link set $DEVICE
    nsenter -t $NETNS -n ip addr add $IPADDR dev $DEVICE
    nsenter -t $NETNS -n ip link set dev $DEVICE address $MACADDR
    nsenter -t $NETNS -n ip link set $DEVICE up
    nsenter -t $NETNS -n ip route replace default via $GW dev $DEVICE

    ip link set veth-${DEVICE}-${NAME} up

    tc qdisc delete dev $DEVICE handle ffff: ingress
    tc qdisc replace dev $DEVICE handle ffff: ingress
    tc qdisc replace dev veth-${DEVICE}-${NAME} handle ffff: ingress
    # tc filter add dev $DEVICE parent ffff: protocol arp action mirred egress mirror dev veth-${DEVICE}-${NAME} continue
    # tc filter add dev $DEVICE parent ffff: protocol ip u32 match u32 0 0 action mirred egress mirror dev veth-${DEVICE}-${NAME} continue

    tc filter replace dev $DEVICE parent ffff: protocol arp u32 match u32 0 0 action mirred egress mirror dev veth-${DEVICE}-${NAME}
    tc filter replace dev $DEVICE parent ffff: protocol ip u32 match ip dport 8192 e000 action mirred egress redirect dev veth-${DEVICE}-${NAME}
    # [8192,8192+8192-1]  // 8192/0xe000
    # 

    tc filter replace dev veth-${DEVICE}-${NAME} parent ffff: protocol arp u32 match u32 0 0 action mirred egress redirect dev ${DEVICE}
    tc filter replace dev veth-${DEVICE}-${NAME} parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ${DEVICE}
}

mirror_device "$@"
