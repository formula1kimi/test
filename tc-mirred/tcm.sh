#!/bin/bash 
set -e -o pipefail

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

    local PORT_START="$((8192 + IDX * 4096))"
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

    add_dynamic_port_forward "$IDX" "$NAME" "$DEV" 
}   

function add_dynamic_port_forward() {
    local IDX=$1
    local CONTAINER=$2
    local DEVICE=$3
    local VETH="veth$IDX"
    local PORT_START="$((8192 + IDX * 4096))"
    local PORT_RANGE="$PORT_START $((PORT_START + 4095))"

    # Find begin filter item index, start from 1000
    local FIDX
    FIDX=$(tc filter  show dev "$DEVICE" ingress  protocol ip pref 1 | (grep -E -o "1::(1[0-9][0-9][0-9])" || true) | (grep -E -o "1[0-9][0-9][0-9]" || true) | sort | tail -n1)
    if [ -z "$FIDX" ]; then
        FIDX=900
    else
        FIDX=$((FIDX+1))
    fi


    # [net]-->[ingress (Host Dev)]-->!!REDIRECT!!-->[(veth host)egress]-->vlink-->[ingress (veth peer) ]-->[process]
    echo "Forward Dynamic port range $PORT_RANGE to container $CONTAINER"
    set -x
    # Even use replace, must specify full handle id. 
    tc filter replace dev "$DEVICE" parent ffff: protocol ip prio 1 handle 1::$((IDX+1)) u32 ht 1: match tcp dst "$PORT_START" f000 action mirred egress redirect dev "$VETH"
    tc filter replace dev "$DEVICE" parent ffff: protocol ip prio 1 handle 2::$((IDX+1)) u32 ht 2: match udp dst "$PORT_START" f000 action mirred egress redirect dev "$VETH"
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
    # Even use replace, must specify full handle id. 
    tc filter replace dev "$DEVICE" parent ffff: protocol arp handle 4::$((IDX+1)) u32 ht 4: match u32 0 0 action mirred egress mirror dev "$VETH" $FILTER_CONTINUE
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
    # Even use replace, must specify full handle id. 
    tc filter replace dev "$DEVICE" parent ffff: protocol ip prio 1 handle 3::$((IDX+1)) u32 ht 3: match u32 0 0 action mirred egress mirror dev "$VETH" $FILTER_CONTINUE
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
        tc qdisc add dev "$DEVICE" handle ffff: ingress
    fi
 
    set -x
    # Can not use replace, need use add, and must check the existance, otherwise will report error.
    if ! tc filter show dev "$DEVICE" parent ffff: protocol ip prio 1 | grep -q "filter u32 chain 0 fh 1: ht divisor 32"; then
        tc filter add dev "$DEVICE" parent ffff: protocol ip  prio 1 handle 1: u32 divisor 32
    fi
    if ! tc filter show dev "$DEVICE" parent ffff: protocol ip prio 1 | grep -q "filter u32 chain 0 fh 2: ht divisor 32"; then
        tc filter add dev "$DEVICE" parent ffff: protocol ip  prio 1 handle 2: u32 divisor 32
    fi
    if ! tc filter show dev "$DEVICE" parent ffff: protocol ip prio 1 | grep -q "filter u32 chain 0 fh 3: ht divisor 32"; then
        tc filter add dev "$DEVICE" parent ffff: protocol ip  prio 1 handle 3: u32 divisor 32
    fi
    if ! tc filter show dev "$DEVICE" parent ffff: protocol arp prio 4 | grep -q "filter u32 chain 0 fh 4: ht divisor 32"; then
        tc filter add dev "$DEVICE" parent ffff: protocol arp  prio 4 handle 4: u32 divisor 32
    fi

    # Even use replace, must specify full handle id. 
    tc filter replace dev "$DEVICE" parent ffff: protocol ip prio 1 handle 800::1 u32 ht 800:: match ip protocol 6 0xff  link 1: offset at 0 mask 0x0f00 shift 6
    tc filter replace dev "$DEVICE" parent ffff: protocol ip prio 1 handle 800::2 u32 ht 800:: match ip protocol 17 0xff  link 2: offset at 0 mask 0x0f00 shift 6
    tc filter replace dev "$DEVICE" parent ffff: protocol ip prio 1 handle 800::3 u32 ht 800:: match ip protocol 1 0xFF link 3:
    tc filter replace dev "$DEVICE" parent ffff: protocol arp prio 4 handle 801::1 u32 ht 801:: match u32 0 0 link 4:
    set +x
}

function find_available_boxidx() {
    NAME_PREFIX=$1
    # find all box container, and their port range
    local containers
    containers="$(docker ps | grep "$NAME_PREFIX" | awk '{print $1}')"

    # generate port range list
    local all_ranges=()
    for i in {0..23}; do
        all_ranges[i]=$((8192+i*4096))
    done

    # get all containers port_range config
    local pid
    local c_range
    for c in $containers; do
        pid=$(docker inspect --format "{{.State.Pid}}" "$c")
        c_range=($(nsenter -t "$pid" -n sysctl -n net.ipv4.ip_local_port_range | awk '{print $1, $2}'))
        for i in {0..23}; do
            r0=${all_ranges[i]}
            r1=$((all_ranges[i]+4095))
            if [ "$r0" -ne "-1" ] && [ "$r0" -ge "${c_range[0]}" ] && [ "$r0" -le "${c_range[1]}" ]; then
                all_ranges[i]="-1"
            fi
            if [ "$r0" -ne "-1" ] && [ "$r1" -ge "${c_range[0]}" ] && [ "$r1" -le "${c_range[1]}" ]; then
                all_ranges[i]="-1"
            fi
        done
    done
    echo "Port Ranges: ${all_ranges[*]}" >&2
    # get smallest idx
    for i in {0..23}; do 
        if [ "${all_ranges[i]}" -ne "-1" ]; then
            echo "$i"
            break
        fi
    done

    # not find available port range, return nothing as error.
}


function prepare_host() {
    # Adjust port range to 32768,60999, which is default settings.
    sysctl net.ipv4.ip_local_port_range="32768 60999"
    # Scan all current listening port and config redirct to host if it's in the 8192~32767
}

# Arg1: device to redirct/map
# Arg2: box container name prefix
# Arg3: container image
# Arg4: extra cmds to box
function add_box() {
    local DEV=$1
    local NAME_PREFIX=$2
    local IMAGE=$3
    if [ -z "$DEV" ] || [ -z "$NAME_PREFIX" ] || [ -z "$IMAGE" ]; then
        echo "Usage: new-box <host dev> <name-prefix> <image> [ cmds/args... ]"
        echo "Example: new-box eth0 net ubuntu:20.04 tail -f /dev/null"
        exit 1
    fi
    shift 3

    # Find a BOXID
    local BOXID
    BOXID=$(find_available_boxidx "$NAME_PREFIX")
    if [ -z "$BOXID" ]; then 
        echo "Can not find availble box id"
        exit 1
    fi
    NAME="$NAME_PREFIX-$BOXID"
    echo "Using box idx: $BOXID, container name: $NAME, dynamic port range: $((8192+4096*BOXID)) ~ $((8192+4096*BOXID+4095))"

    # Remove the existed box
    docker rm -f "$NAME_PREFIX-$BOXID" 2>/dev/null || true

    # Always try to init the fiter rules structure
    init_filter_ht "$DEV"

    echo "=============================$NAME=============================="
    start_container "$NAME" "$IMAGE" $@
    init_container_net  "$BOXID" "$NAME" "$DEV" 
    add_arp_forward "$BOXID" "$NAME" "$DEV" continue
    add_icmp_forward "$BOXID" "$NAME" "$DEV" continue
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
    prep-host):
        prepare_host $@
        ;;
    add-box):
        add_box $@
        ;;
    add-port):
        add_port $@
        ;;
    *):
        echo "Usage: $0 <action> [action args...]"
        echo "Action: prepare_host, add-box, add-port"
        ;;
    esac
}

main "$@"
