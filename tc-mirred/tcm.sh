#!/bin/bash 
set -e -o pipefail

NAME_PREFIX=
function start_container() {
    local NAME=$1
    local IMAGE=$2
    shift 2
    docker run -d --privileged --name "${NAME}"  --network none "$IMAGE" $@
}

function init_container_net() {
    local IPADDR MACADDR GW VETH
    local IDX=$1
    local CONTAINER=$2
    local DEVICE=$3

    GW=$(ip route | grep default | awk '{print $3}')
    echo "Gateway: $GW"

    VETH="veth$IDX"
    echo "Veth host: $VETH"

    NETNS=$(docker inspect --format "{{.State.Pid}}" "${CONTAINER}")
    echo "NetNS: $NETNS"

    IPADDR=$(ip -4 addr show dev "$DEVICE" | grep inet | awk '{print $2}')
    MACADDR=$(ip link show dev "$DEVICE" | grep link | awk '{print $2}')
    echo "Veth peer IP: $IPADDR MAC: $MACADDR"

    local PORT_START="$((IDX * 4096))"
    local PORT_RANGE="$PORT_START $((PORT_START + 4095))"
    echo "Port Range: $PORT_RANGE"

    set -x
    # veth device can be removed when container is removed
    ip link add "$VETH" type veth peer name "$DEVICE" netns "$NETNS"
    nsenter -t "$NETNS" -n ip link set "$DEVICE"
    nsenter -t "$NETNS" -n ip addr add "$IPADDR" dev "$DEVICE"
    nsenter -t "$NETNS" -n ip link set dev "$DEVICE" address "$MACADDR"
    nsenter -t "$NETNS" -n ip link set "$DEVICE" up
    nsenter -t "$NETNS" -n ip route replace default via "$GW" dev "$DEVICE"
    nsenter -t "$NETNS" -n sysctl net.ipv4.ip_local_port_range="${PORT_RANGE/-/ }"
    nsenter -t "$NETNS" -n sysctl net.ipv4.icmp_echo_ignore_all=1
    nsenter -t "$NETNS" -n sysctl net.ipv4.conf.all.arp_ignore=8

    ip link set "$VETH" up
    set +x

    # [net]<--[egress (Host Dev)]<--!!REDIRECT!!<--[(veth host)ingress]<--vlink<--[egress (veth peer)]<--[process]
    echo "Forward container ALL traffic from $CONTAINER to host $DEVICE"
    set +x
    tc qdisc replace dev "$VETH" handle ffff: ingress
    tc filter replace dev "$VETH" parent ffff: protocol ip prio 1 u32 match u32 0 0 action mirred egress redirect dev "${DEVICE}"
    tc filter replace dev "$VETH" parent ffff: protocol arp u32 match u32 0 0 action mirred egress redirect dev "${DEVICE}"
    tc filter replace dev "$VETH" parent ffff: protocol ip prio 1 u32 match ip protocol 1 0xFF action mirred egress redirect dev "$DEVICE"
    set +x
}   

function add_dynamic_port_forward() {
    local IDX=$1
    local CONTAINER=$2
    local DEVICE=$3
    local VETH="veth$IDX"
    local PORT_START="$((IDX * 4096))"
    local PORT_RANGE="$PORT_START $((PORT_START + 4095))"

    # [net]-->[ingress (Host Dev)]-->!!REDIRECT!!-->[(veth host)egress]-->vlink-->[ingress (veth peer) ]-->[process]
    echo "Forward Dynamic port range $PORT_RANGE to container $CONTAINER"
    set -x
    tc filter add dev "$DEVICE" parent ffff: protocol ip prio 1 u32 ht 1: match tcp dst "$PORT_START" f000 action mirred egress redirect dev "$VETH"
    tc filter add dev "$DEVICE" parent ffff: protocol ip prio 1 u32 ht 2: match udp dst "$PORT_START" f000 action mirred egress redirect dev "$VETH"
    set +x
}

function add_arp_forward() {
    local IDX=$1
    local CONTAINER=$2
    local DEVICE=$3
    local VETH="veth$IDX"
    local FILTER_CONTINUE=$4
    echo "Mirror ARP to container $CONTAINER"
    set -x
    tc filter add dev "$DEVICE" parent ffff: protocol arp u32 ht 4: match u32 0 0 action mirred egress mirror dev "$VETH" $FILTER_CONTINUE
    set +x
}

function add_icmp_forward() {
    local IDX=$1
    local CONTAINER=$2
    local DEVICE=$3
    local VETH="veth$IDX"
    local FILTER_CONTINUE=$4
    echo "Mirror ICMP to container $CONTAINER"
    set -x
    tc filter add dev "$DEVICE" parent ffff: protocol ip prio 1 u32 ht 3: match u32 0 0 action mirred egress mirror dev "$VETH" $FILTER_CONTINUE
    set +x
}

function add_static_port_forward() {
    local IDX=$1
    local CONTAINER=$2
    local DEVICE=$3
    VETH="veth$IDX"
    STATIC_PORTS=$4
    local STATIC_PORTS="${STATIC_PORTS/,/ }"

    # Find begin filter item index.
    local FIDX
    FIDX=$(tc filter  show dev "$DEVICE" ingress  protocol ip pref 1 | (grep -E -o "2::(1[0-9][0-9])" || true) | (grep -E -o "1[0-9][0-9]" || true) | sort | tail -n1)
    if [ -z "$FIDX" ]; then
        FIDX=100
    else
        FIDX=$((FIDX+1))
    fi

    for PORT in ${STATIC_PORTS}; do 
        echo "Mirror static port $PORT to container $CONTAINER" 
        if ! echo "$PORT" | grep -q -E '^[0-9]+$'; then
            echo "Bad port number: $PORT, skip"
            continue
        fi
        set -x
        tc filter add dev "$DEVICE" parent ffff: protocol ip prio 1 handle 1::$FIDX u32 ht 1: match tcp dst "$PORT" 0xffff action mirred egress redirect dev "$VETH"
        tc filter add dev "$DEVICE" parent ffff: protocol ip prio 1 handle 2::$FIDX u32 ht 2: match udp dst "$PORT" 0xffff action mirred egress redirect dev "$VETH"
        set +x
        FIDX=$((FIDX+1))
    done
}

function init_filter_ht() {
    local DEVICE=$1
    if ! (tc qdisc show dev "$DEVICE" ingress | grep -q ingress); then
        echo "Create $DEVICE ingress qdisc"
        tc qdisc replace dev "$DEVICE" handle ffff: ingress
    fi
 
    set -x
    tc filter add dev "$DEVICE" parent ffff: protocol ip  prio 1 handle 1: u32 divisor 32
    tc filter add dev "$DEVICE" parent ffff: protocol ip  prio 1 handle 2: u32 divisor 32
    tc filter add dev "$DEVICE" parent ffff: protocol ip  prio 1 handle 3: u32 divisor 32
    tc filter add dev "$DEVICE" parent ffff: protocol arp  prio 4 handle 4: u32 divisor 32

    tc filter add dev "$DEVICE" parent ffff: protocol ip prio 1 u32 ht 800:: match ip protocol 6 0xff  link 1: offset at 0 mask 0x0f00 shift 6
    tc filter add dev "$DEVICE" parent ffff: protocol ip prio 1 u32 ht 800:: match ip protocol 17 0xff  link 2: offset at 0 mask 0x0f00 shift 6
    tc filter add dev "$DEVICE" parent ffff: protocol ip prio 1 u32 ht 800:: match ip protocol 1 0xFF link 3:
    tc filter add dev "$DEVICE" parent ffff: protocol arp prio 4 u32 match u32 0 0 link 4:
    set +x
}


function init() {
    local COUNT=$1
    local DEV=$2
    NAME_PREFIX=$3
    local IMAGE=$4
    if [ -z "$COUNT" ] || [ -z "$DEV" ] || [ -z "$NAME_PREFIX" ] || [ -z "$IMAGE" ]; then
        echo "Usage: init <count> <host dev> <name-prefix> <image> [ cmds/args... ]"
        echo "Example: init 2 eth0 net ubuntu:20.04 tail -f /dev/null"
        exit 1
    fi
    shift 4

    docker rm -f $NAME_PREFIX-{1..15} || true
    tc filter del dev "$DEV" ingress || true

    init_filter_ht "$DEV"

    local IDX=1
    while [ "$IDX" -le "$COUNT" ]; do
        NAME="$NAME_PREFIX-$IDX"
        echo "=============================$NAME=============================="
        start_container "$NAME" "$IMAGE" $@
        init_container_net  "$IDX" "$NAME" "$DEV" 
        add_dynamic_port_forward "$IDX" "$NAME" "$DEV" 
        if [ "$IDX" -lt "$COUNT" ]; then
            add_arp_forward "$IDX" "$NAME" "$DEV" continue
            add_icmp_forward "$IDX" "$NAME" "$DEV" continue
        else
            add_arp_forward "$IDX" "$NAME" "$DEV"
            add_icmp_forward "$IDX" "$NAME" "$DEV"
        fi
        IDX=$((IDX+1))
    done

}

function add_port() {
    local IDX=$1
    local DEV=$2
    local PORTS=$3
    local NAME="$NAME_PREFIX-$IDX"
    if [ -z "$IDX" ] || [ -z "$DEV" ] || [ -z "$PORTS" ]; then
        echo "Usage: add-port <index> <host dev> <ports>"
        echo "Example: add-port 1 eth0 3412,10456"
        exit 1
    fi
    add_static_port_forward "$IDX" "$NAME" "$DEV" "$PORTS"
}

function main() {
    local ACTION=$1
    if [ -n "$ACTION" ]; then shift 1; fi
    case $ACTION in 
    init)
        init $@
        ;;
    add-port)
        add_port $@
        ;;
    *)
        echo "Usage: $0 <action> [action args...]"
        echo "Action: init, add-port"
        ;;
    esac
}

main "$@"
