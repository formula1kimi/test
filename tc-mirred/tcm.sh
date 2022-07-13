#!/bin/bash 
set -e -o pipefail

#==================================
# Changelogs
#==================================
# 2022/06/30: Version 0.6: First release
# 2022/07/13: Version 0.7: Re-structure

VERSION="0.6"

NAME_PREFIX="pai-box"
TYPE="nop"

ACTION=

function _nsenter() {
    /usr/bin/nsenter "$@"
}

function log() {
    echo -e "tcm:" "$@" >&2
}

function start_port_byid() {
    local boxid=$1
    echo $((8192 + 4096 * (boxid - 1)))
}


function end_port_byid() {
    local boxid=$1
    echo $((8192 + 4096 * (boxid - 1) + 4095))
}

function start_container() {
    local NAME=$1
    local IMAGE=$2
    shift 2
    docker run -d --privileged --name "${NAME}"  --network none "$IMAGE" $@
}

function find_netdev() {
    ip route show | grep default | grep -o -E "dev [^ ]+ " | awk '{print $2}'
}

# arg1: boxid
# arg2: container name
# arg3: device
function init_container_net() {
    log ">>> INIT-CONTAINER-NET"
    local IPADDR DEVICE_MAC GW VETH
    local IDX=$1
    local CONTAINER=$2
    local DEVICE=$3

    # Get default gateway
    if [[ "$(ip route get 114.114.114.114 | head -n1)" =~ via\ ([0-9.]+)  ]]; then 
        GW=${BASH_REMATCH[1]}; 
    fi
    log "  Gateway: $GW"

    VETH="veth$IDX"
    log "  Veth host: $VETH"

    NETNS=$(docker inspect --format "{{.State.Pid}}" "${CONTAINER}")
    log "  NetNS: $NETNS"

    IPADDR=$(ip -4 addr show dev "$DEVICE" | (grep inet | awk '{print $2}' || true))
    if [ -z "$IPADDR" ]; then
        log "  Can not find IP address of device: $DEVICE"
        exit 1;
    fi
    DEVICE_MAC=$(ip link show dev "$DEVICE" | (grep -E -o 'link/ether [0-9a-f:]{17}' || true) | awk '{print $2}')
    log "  Veth peer IP: $IPADDR MAC: $DEVICE_MAC"

    local PORT_START
    PORT_START=$(start_port_byid "$IDX")
    local PORT_END
    PORT_END=$(end_port_byid "$IDX")
    local PORT_RANGE="$PORT_START $PORT_END"
    log "  Use Port Range: $PORT_RANGE"

    # veth device can be removed when container is removed
    if ip link show "$VETH" &>/dev/null; then
        log "  Remove old vethpair: $VETH"
        ip link del "$VETH"
    fi
    log "  Create vethpair: $VETH <---> virtual $DEVICE"
    ip link add "$VETH" type veth peer name "$DEVICE" netns "$NETNS"
    log "  Setup container network interface: $VETH <---> virtual $DEVICE"
    _nsenter -t "$NETNS" -n ip link set "$DEVICE"
    _nsenter -t "$NETNS" -n ip addr add "$IPADDR" dev "$DEVICE"
    # If host netdev don't have ethernet, such as PPP, fake one.
    local DEVICE_NO_ETHER=0
    if [ -z "$DEVICE_MAC" ]; then
        DEVICE_MAC="12:12:12:12:12:12"
        DEVICE_NO_ETHER=1
    fi
    _nsenter -t "$NETNS" -n ip link set dev "$DEVICE" address "$DEVICE_MAC"
    _nsenter -t "$NETNS" -n ip link set "$DEVICE" up
    _nsenter -t "$NETNS" -n ip route replace "$GW" dev "$DEVICE"
    _nsenter -t "$NETNS" -n ip route replace default via "$GW" dev "$DEVICE"
    _nsenter -t "$NETNS" -n sysctl net.ipv4.ip_local_port_range="${PORT_RANGE/-/ }"
    _nsenter -t "$NETNS" -n sysctl net.ipv4.icmp_echo_ignore_all=1
    _nsenter -t "$NETNS" -n sysctl net.ipv4.conf.all.arp_ignore=8
    ip link set "$VETH" up
    sysctl net.ipv4.conf.${VETH}.rp_filter=0

    # [net]<--[egress (Host Dev)]<--!!REDIRECT!!<--[(veth host)ingress]<--vlink<--[egress (veth peer)]<--[process]
    log "  Forward container ALL traffic from $CONTAINER to host $DEVICE"
    tc qdisc replace dev "$VETH" handle ffff: ingress
    if [ "$DEVICE_NO_ETHER" -eq 0 ]; then
        tc filter replace dev "$VETH" parent ffff: protocol ip prio 1 u32 match u32 0 0 \
            action mirred egress redirect dev "${DEVICE}"
        tc filter replace dev "$VETH" parent ffff: protocol arp u32 match u32 0 0 action mirred egress redirect dev "${DEVICE}"
    else
        # If host dev has no L2 header(PPP), ARP not work, need add static one, any fake MAC can be used, we use host veth MAC. 
        # This is OK, because the L2 will be remove before redirect.
        local VETH_MAC
        VETH_MAC=$(ip link show dev "$VETH" | (grep -E -o "link/ether [0-9a-f:]{17}" || true) | awk '{print $2}')
        _nsenter -t "$NETNS" -n ip neigh del "$GW" dev "$DEVICE" 2>/dev/null || true
        _nsenter -t "$NETNS" -n ip neigh add "$GW" dev "$DEVICE" lladdr "$VETH_MAC"

        # The host dev don't have mac address, use ebpf to remove ether header
        tc filter replace dev "$VETH" parent ffff: protocol ip prio 1 u32 match u32 0 0 \
	        action bpf obj ./tc_push_ether.bpf.o sec pull_ether \
            action mirred egress redirect dev "${DEVICE}"
        # The physical device don't have mac address, don't mirror ARP to it, useless.
    fi
}   

function uninit_container_net() {
    log ">>> uninit_container_net"
    local IDX=$1
    local CONTAINER=$2
    local DEVICE=$3
    local VETH="veth$IDX"
    log "Veth host: $VETH"
        
    NETNS=$(docker inspect --format "{{.State.Pid}}" "${CONTAINER}")
    log "NetNS: $NETNS"

    log "Remove vethpair: $VETH <---> virtual $DEVICE"
    ip link set "$VETH" down || true;
    ip link del "$VETH" || true;
}

# arg1: boxid
# arg2: device
function add_dynamic_port_forward() {
    local IDX=$1
    local DEVICE=$2
    local VETH="veth$IDX"

    local PORT_START
    PORT_START=$(start_port_byid "$IDX")
    local PORT_END
    PORT_END=$(end_port_byid "$IDX")
    local PORT_RANGE="$PORT_START $PORT_END"

    # dynamic port range forwarding started from 900
    local FIDX=$((900+IDX))
    if [ $FIDX -gt 999 ]; then
        log "Error, filter index for dynamic port forward exceed 999, abort"
        exit 1
    fi

    local VETH_MAC
    VETH_MAC=$(ip link show dev "$VETH" | (grep -E -o "link/ether [0-9a-f:]{17}" || true) | awk '{print $2}')
    local PEER_MAC DEVICE_MAC
    DEVICE_MAC=$(ip link show dev "$DEVICE" | (grep -E -o "link/ether [0-9a-f:]{17}" || true) | awk '{print $2}')

    # [net]-->[ingress (Host Dev)]-->!!REDIRECT!!-->[(veth host)egress]-->vlink-->[ingress (veth peer) ]-->[process]
    log "Forward Dynamic port range $PORT_RANGE to boxid $IDX"
    # Even use replace, must specify full handle id. 
    if [ -n "$DEVICE_MAC" ]; then
        tc filter replace dev "$DEVICE" parent ffff: protocol ip prio 1 handle 1::$FIDX u32 ht 1: match tcp dst "$PORT_START" f000 \
            action mirred egress redirect dev "$VETH"
        tc filter replace dev "$DEVICE" parent ffff: protocol ip prio 1 handle 2::$FIDX u32 ht 2: match udp dst "$PORT_START" f000 \
            action mirred egress redirect dev "$VETH"
    else
        # Host device don't have mac address(PPP), we need build it, use faked MAC in sandbox netdev.
        PEER_MAC="12:12:12:12:12:12"
        tc filter replace dev "$DEVICE" parent ffff: protocol ip prio 1 handle 1::$FIDX u32 ht 1: match tcp dst "$PORT_START" f000 \
	        action bpf obj ./tc_push_ether.bpf.o sec push_ether  \
            action skbmod set dmac $PEER_MAC set smac  "$VETH_MAC" set etype 0x0800 \
            action mirred egress redirect dev "$VETH"
        tc filter replace dev "$DEVICE" parent ffff: protocol ip prio 1 handle 2::$FIDX u32 ht 2: match udp dst "$PORT_START" f000 \
	        action bpf obj ./tc_push_ether.bpf.o sec push_ether \
            action skbmod set dmac $PEER_MAC set smac  "$VETH_MAC" set etype 0x0800 \
            action mirred egress redirect dev "$VETH"
    fi
}

# arg1: boxid
# arg2: device
function remove_dynamic_port_forward() {
    local IDX=$1
    local DEVICE=$2
    local VETH="veth$IDX"

    # dynamic port range forwarding started from 900
    local FIDX=$((900+IDX))
    if [ $FIDX -gt 999 ]; then
        log "Error, filter index for dynamic port forward exceed 999, abort"
        exit 1
    fi
    log "Remove forward dynamic port range $PORT_RANGE from boxid $IDX"
    tc filter del dev "$DEVICE" parent ffff: protocol ip prio 1 handle 1::$FIDX u32 || true
    tc filter del dev "$DEVICE" parent ffff: protocol ip prio 1 handle 2::$FIDX u32 || true
}

function add_arp_forward() {
    local IDX=$1
    local DEVICE=$2
    local VETH="veth$IDX"
    local FILTER_CONTINUE=$3
    log "Add Mirror ARP to boxid: $IDX"
    # Even use replace, must specify full handle id. 
    tc filter replace dev "$DEVICE" parent ffff: protocol arp prio 4 handle 4::$IDX u32 ht 4: match u32 0 0 action mirred egress mirror dev "$VETH" $FILTER_CONTINUE
}

function remove_arp_forward() {
    local IDX=$1
    local DEVICE=$2
    local VETH="veth$IDX"
    log "Remove Mirror ARP from boxid: $IDX"
    tc filter del dev "$DEVICE" parent ffff: protocol arp prio 4 handle 4::$IDX u32 || true
}

function add_icmp_forward() {
    local IDX=$1
    local DEVICE=$2
    local VETH="veth$IDX"
    local FILTER_CONTINUE=$3
    log "Add Mirror ICMP to boxid: $IDX"

    local VETH_MAC
    VETH_MAC=$(ip link show dev "$VETH" | (grep -E -o "link/ether [0-9a-f:]{17}" || true) | awk '{print $2}')
    local DEVICE_MAC
    DEVICE_MAC=$(ip link show dev "$DEVICE" | (grep -E -o "link/ether [0-9a-f:]{17}" || true) | awk '{print $2}')
    # Even use replace, must specify full handle id. 
    if [ -n "$DEVICE_MAC" ]; then
        tc filter replace dev "$DEVICE" parent ffff: protocol ip prio 1 handle 3::$IDX u32 ht 3: match u32 0 0 \
            action mirred egress mirror dev "$VETH" $FILTER_CONTINUE
    else
        # Host dev has no L2, Need add new ether header before mirred to box
        # Fixme: after push ether, can L3 correctly handle this pkt
        PEER_MAC="12:12:12:12:12:12"
        tc filter replace dev "$DEVICE" parent ffff: protocol ip prio 1 handle 3::$IDX u32 ht 3: match u32 0 0 \
	        action bpf obj ./tc_push_ether.bpf.o sec push_ether \
            action skbmod set dmac "$PEER_MAC" set smac  "$VETH_MAC" set etype 0x0800 \
	        action mirred egress mirror dev "$VETH" $FILTER_CONTINUE
    fi
}

function remove_icmp_forward() {
    local IDX=$1
    local DEVICE=$2
    log "Remove Mirror ICMP from boxid: $IDX"
    tc filter del dev "$DEVICE" parent ffff: protocol ip prio 1 handle 3::$IDX u32 || true
}


function add_static_port_forward() {
    local IDX=$1
    local CONTAINER=$2
    local DEVICE=$3
    local VETH="veth$IDX"
    # local STATIC_PORTS="${STATIC_PORTS/,/ }"
    local STATIC_PORTS=$4

    # Filter id for staic port is determined by idx 1:1~49, then 2:50~99, and so on, each container have 50 idx space.
    # filter id 0 can not be used, so first container only have 49 filter available.
    local FIDX_START=$(((IDX-1)*50))
    if [ $FIDX_START -eq 0 ]; then FIDX_START=1; fi
    local FIDX_END=$((FIDX_START+49))
    local H=$((FIDX_START / 100))
    local D
    if [ $((FIDX_START - 100*H)) -lt 50 ]; then 
        D="[0-4][0-9]"
    else 
        D="[5-9][0-9]"
    fi
    if [ "$H" -eq 0 ]; then 
        H="";
        if [ $FIDX_START -lt 50 ]; then 
            D="[0-4]?[0-9]"
        fi
    fi

    FIDX=$(tc filter  show dev "$DEVICE" ingress  protocol ip pref 1 | (grep -E -o "1::$H$D " || true) | cut -b4- | sort -n | tail -n1)
    if [ -z "$FIDX" ]; then
        FIDX=$FIDX_START
    else
        FIDX=$((FIDX+1))
    fi

    if [ $FIDX -gt $FIDX_END ]; then
        log "Error, filter index for static port forward exceed $FIDX_END, abort"
        exit 1
    fi


    for PORT in ${STATIC_PORTS}; do 
        log "Redirect static port $PORT to container $CONTAINER" 
        if ! echo "$PORT" | grep -q -E '^[0-9]+$'; then
            log "Bad port number: $PORT, skip"
            continue
        fi
        tc filter add dev "$DEVICE" parent ffff: protocol ip prio 1 handle 1::$FIDX u32 ht 1: match tcp dst "$PORT" 0xffff action mirred egress redirect dev "$VETH"
        tc filter add dev "$DEVICE" parent ffff: protocol ip prio 1 handle 2::$FIDX u32 ht 2: match udp dst "$PORT" 0xffff action mirred egress redirect dev "$VETH"
        FIDX=$((FIDX+1))
        if [ $FIDX -gt $FIDX_END ]; then
            log "Error, filter index for static port forward exceed $FIDX_END, abort"
            exit 1
        fi
    done
}

function remove_static_port_forward() {
    local IDX=$1
    local DEVICE=$2
    VETH="veth$IDX"
    
    # find the filter id range of this boxid
    local FIDX_START=$(((IDX-1)*50))
    if [ $FIDX_START -eq 0 ]; then FIDX_START=1; fi
    local FIDX_END=$((FIDX_START+49))
    local H=$((FIDX_START / 100))
    local D
    if [ $((FIDX_START - 100*H)) -lt 50 ]; then 
        D="[0-4][0-9]"
    else 
        D="[5-9][0-9]"
    fi
    if [ "$H" -eq 0 ]; then 
        H="";
        if [ $FIDX_START -lt 50 ]; then 
            D="[0-4]?[0-9]"
        fi
    fi
    FIDXS=$(tc filter  show dev "$DEVICE" ingress  protocol ip pref 1 | (grep -E -o "1::$H$D " || true) | cut -b4- | sort -n)
    FIDXS="${FIDXS//$'\n'/ }"
    log "Remove filter ids for staitc port forward: $FIDXS"
    for FIDX in $FIDXS; do 
        tc filter del dev "$DEVICE" ingress protocol ip pref 1 handle 1::$FIDX u32
        tc filter del dev "$DEVICE" ingress protocol ip pref 1 handle 2::$FIDX u32
    done
}



function set_host_static_ports() {
    local DEVICE=$1
    # scan all listening ports, and don't redirect them if they are in redirection port range: 8192 ~ 32767
    local listen_ports
    listen_ports=$(ss -ntulpH | grep -v "127\.0\.0\.1" | awk '{print $5}' | awk -F: '{print $NF}' | sort -nu)
    local rule_ports
    for port in $listen_ports; do
        if [ "$port" -ge 8192 ] && [ "$port" -lt 32768 ]; then 
            rule_ports+="$port "
        fi
    done

    FIDX=$(tc filter  show dev "$DEVICE" ingress  protocol ip pref 1 | (grep -E -o "1::8[0-9][0-9] " || true) | cut -b4- | sort -n | tail -n1)
    if [ -z "$FIDX" ]; then
        FIDX=800
    else
        FIDX=$((FIDX+1))
    fi

    if [ $FIDX -gt 899 ]; then
        log "Error, filter index for host port forward exceed 899, abort"
        exit 1
    fi

    log "Host static ports never redirect: $rule_ports"
    for PORT in $rule_ports; do 
        log "skip redirect host port: $PORT" 
        if ! echo "$PORT" | grep -q -E '^[0-9]+$'; then
            log "Bad port number: $PORT, skip"
            continue
        fi
        # Check duplication
        if tc filter show dev "$DEVICE" ingress protocol ip pref 1 | grep '1::8[0-9][0-9]' -A1 | grep -q $(printf "%08x/0000ffff" $PORT); then
            log "  host port $PORT, already added rule, skip"
            continue
        fi
 
        tc filter add dev "$DEVICE" parent ffff: protocol ip prio 1 handle 1::$FIDX u32 ht 1: match tcp dst "$PORT" 0xffff action ok
        tc filter add dev "$DEVICE" parent ffff: protocol ip prio 1 handle 2::$FIDX u32 ht 2: match udp dst "$PORT" 0xffff action ok
        FIDX=$((FIDX+1))
        if [ $FIDX -gt 899 ]; then
            log "Error, filter index for host port forward exceed 899, abort"
            exit 1
        fi
    done
 
}

function update_reserved_ports() {
    local DEVICE$1
    local reserved_hex_ports
    reserved_hex_ports=$(tc filter show dev $DEVICE ingress | (grep -E "fh 1::([0-9] |[0-9][0-9] |[0-7][0-9][0-9] )" -A1 || true) | awk '/match/ { if(match($0, "([0-9a-f]{8})/", a)) print a[1]}')
    reserved_hex_ports=${reserved_hex_ports//$'\n'/ }
    local reserved_ports
    for p in $reserved_hex_ports; do
        reserved_ports+="$(printf %d 0x$p),"
    done
    reserved_ports="${reserved_ports%,*}"
    log "Update Host Reserved Ports: $reserved_ports"
    sysctl net.ipv4.ip_local_reserved_ports="$reserved_ports"

    boxes=$(find_all_box)
    for box in $boxes; do
        log "Update $box's Reserved Ports: $reserved_ports"
        pid=$(docker inspect --format "{{.State.Pid}}" "$box")
        _nsenter -t "$pid" -n sysctl net.ipv4.ip_local_reserved_ports="$reserved_ports"
    done
}

function init_device_filter() {
    log ">>> INIT DEVICE FILTER"
    local DEVICE=$1

    if [ "$DEVICE" == "ALL" ]; then
        DEVICE=$(find_netdev)
        log "ALL interface: $DEVICE"
    fi

    if ! (tc qdisc show dev "$DEVICE" ingress | grep -q ingress); then
        log "Create $DEVICE ingress qdisc"
        tc qdisc add dev "$DEVICE" handle ffff: ingress
    fi
 
    # Can not use replace, need use add, and must check the existance, otherwise will report error.
    DATA=$(tc filter show dev "$DEVICE" parent ffff: protocol ip prio 1)
    if ! echo "$DATA" | grep -q "filter u32 chain 0 fh 1: ht divisor 32"; then
        tc filter add dev "$DEVICE" parent ffff: protocol ip  prio 1 handle 1: u32 divisor 32
    fi
    if ! echo "$DATA" | grep -q "filter u32 chain 0 fh 2: ht divisor 32"; then
        tc filter add dev "$DEVICE" parent ffff: protocol ip  prio 1 handle 2: u32 divisor 32
    fi
    if ! echo "$DATA" | grep -q "filter u32 chain 0 fh 3: ht divisor 32"; then
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

    set_host_static_ports "$DEVICE"

}

function clear_device_filter() {
    log ">>> CLEAR DEVICE FILTER"
    local DEVICE=$1

    if [ "$DEVICE" == "ALL" ]; then
        DEVICE=$(find_netdev)
        log "ALL interface: $DEVICE"
    fi

    tc qdisc del dev "$DEVICE" ingress || true
}

function init_host() {
    log "INIT-HOST"
    # Adjust port range to 32768,60999, which is default settings.
    sysctl net.ipv4.ip_local_port_range="32768 60999"
    # This for L3 forward support. (L2 redirect mode don't need it)
    sysctl net.ipv4.conf.all.accept_local=1
    sysctl net.ipv4.conf.all.rp_filter=0
}

function clear_host() {
    log "CLEAR-HOST: nothing"
}

function find_all_box() {
    local boxes
    boxes=$(docker ps | awk '//{if (match($NF, "^'"$NAME_PREFIX"'-.*$", a)) print a[0]}')
    boxes=${boxes//$'\n'/ }
    echo "$boxes"
}

function find_available_boxidx() {
    # find all box container, and their port range
    local containers
    containers="$(find_all_box)"
    # generate port range list
    local all_ranges=()
    for i in {0..5}; do
        all_ranges[i]=$((8192+i*4096))
    done

    # get all containers port_range config
    local pid
    local c_range
    for c in $containers; do
        pid=$(docker inspect --format "{{.State.Pid}}" "$c")
        c_range=($(_nsenter -t "$pid" -n sysctl -n net.ipv4.ip_local_port_range | awk '{print $1, $2}'))
        #log "Container [$c] already has port-range: ${c_range[*]}" 
        for i in {0..5}; do
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
    log "Port Ranges Map: ${all_ranges[*]}" 
    # get smallest idx
    for i in {0..5}; do 
        if [ "${all_ranges[i]}" -ne "-1" ]; then
            echo "$((i+1))"   # ID start with 1
            break
        fi
    done

    # not find available port range, return nothing as error.
}


# Arg1: box container name
# Arg2: container image
# Arg3: extra cmds to box
function add_box() {
    local NAME=$1
    local IMAGE=$2
    if [ -z "$NAME" ] || [ -z "$IMAGE" ]; then
        log "Usage: add-box <container name> <image> [ cmds/args... ]"
        log "Example: add-box net ubuntu:20.04 tail -f /dev/null"
        exit 1
    fi
    shift 2

    start_container "$NAME" "$IMAGE" "$@"
}

function del_box() {
    local NAME=$1
    remove_box_link "$NAME" ALL
    docker rm -f "$NAME"
}

function create_box_link() {
    log ">>> INIT BOX"
    local NAME=$1
    local DEVICE=$2
    if [ -z "$DEVICE" ] || [ -z "$NAME" ] ; then
        help
    fi

    if ! docker ps --format "{{.ID}} {{.Names}}" | grep -q "$NAME"; then 
        log "Error: can not find container"
        exit 1
    fi

    if [ "$DEVICE" == "ALL" ]; then
        DEVICE=$(find_netdev)
        log "ALL interface: $DEVICE"
    fi

    # Always init the host fitler hash table.
    init_host
    init_device_filter "$DEVICE"
 
    log "Find boxid for the container..."
    local BOXID
    # The container may be already the inited box
    BOXID=$(find_container_boxid "$NAME")
    if [ -n "$BOXID" ]; then
        log "This container already has valid port range and id: $BOXID"
    else
        log "Allocate new boxid for container: $NAME"
        BOXID=$(find_available_boxidx)
    fi

    if [ -z "$BOXID" ]; then 
        log "Can not use any availble box id"
        exit 1
    fi

    log "Using box idx: $BOXID for container: $NAME"
    init_container_net  "$BOXID" "$NAME" "$DEVICE" 
    add_dynamic_port_forward "$BOXID" "$DEVICE" 
    add_arp_forward "$BOXID" "$DEVICE" continue   
    add_icmp_forward "$BOXID" "$DEVICE" continue
}

function remove_box_link() {
    local NAME=$1
    local DEVICE=$2
    log ">>> Remove box[$NAME] link: $DEVICE"
    if [ -z "$DEVICE" ] || [ -z "$NAME" ] ; then
        help
    fi

    if [ "$DEVICE" == "ALL" ]; then
        DEVICE=$(find_netdev)
        log "ALL interface: $DEVICE"
    fi


    # Find a BOXID by prefix
    local BOXID
    BOXID=$(find_container_boxid "$NAME")
    if [ -z "$BOXID" ]; then
        log "Error: Can not get boxid of container $NAME, make sure it's sandbox container"
        exit 1
    fi
 
    log "Container: $NAME box id = $BOXID"
    uninit_container_net "$BOXID" "$NAME" "$DEVICE"
    remove_dynamic_port_forward "$BOXID" "$DEVICE"
    remove_arp_forward "$BOXID" "$DEVICE"
    remove_icmp_forward "$BOXID" "$DEVICE"
    remove_static_port_forward "$BOXID" "$DEVICE"
    update_reserved_ports "$DEVICE"
}

function find_container_boxid() {
    local NAME_OR_ID=$1
   # generate port range list
    local all_ranges=()
    for i in {0..5}; do
        all_ranges[i]=$((8192+i*4096))
    done

    local pid
    pid=$(docker inspect --format "{{.State.Pid}}" "${NAME_OR_ID}")
    if [ -z "$pid" ]; then
        log "Error: Can not find container: $NAME_OR_ID" 
        return
    fi
    port_range_start="$(_nsenter -t "$pid" -n sysctl -n net.ipv4.ip_local_port_range | awk '{print $1}')"

    if [ -n "$port_range_start" ] && grep -q "$port_range_start" <<< "${all_ranges[*]}"; then
        local idx
        idx=$(((port_range_start - 8192) / 4096 + 1))
        echo $idx
    fi
}

function set_box_ports() {
    local NAME=$1
    local DEVICE=$2
    shift 2
    local PORTS="$*"
    if [ -z "$NAME" ] || [ -z "$DEVICE" ] || [ -z "$PORTS" ]; then
        log "Usage: $ACTION <host dev> <ports> <container name>"
        log "Example: $ACTION  eth0 3412,10456 net-1"
        exit 1
    fi

    if [ "$DEVICE" == "ALL" ]; then
        DEVICE=$(find_netdev)
        log "ALL interface: $DEVICE"
    fi

    local BOXID
    BOXID=$(find_container_boxid "$NAME")
    if [ -z "$BOXID" ]; then
        log "Error: Can not get boxid of container $NAME, make sure it's sandbox container"
        exit 1
    fi
    log "Add static port to $NAME with id: $BOXID"
    add_static_port_forward "$BOXID" "$NAME" "$DEVICE" "$PORTS"

    update_reserved_ports "$DEVICE"
}


function list() {
    local DEVICE=$1

    if [ -z "$DEVICE" ]; then
        log "net dev is not specified"
        exit 1
    fi

    # Merge multiple lines to single one for one filter item.
    LINES=()
    MLINE=
    while read -r LINE; do
        if [[ "$LINE" =~ ^filter ]]; then
            if [ -n "$MLINE" ]; then LINES+=("$MLINE"); fi
            MLINE="$LINE"
        else 
            MLINE+=" $LINE"
        fi
    done <<< "$(tc filter show dev $DEVICE ingress)"
    log "==========================$DEVICE======================="
    for LINE in "${LINES[@]}"; do
        if [[ "$LINE" =~ fh[[:space:]]+(1::[0-9]?[0-9][[:space:]]|1::[1-7][0-9][0-9][[:space:]]).*match[[:space:]]([0-9a-f]{8}/[0-9a-f]{8}).*mirred[[:space:]]\((.*)\) ]]; then
            log "${BASH_REMATCH[1]}\t TCP REDIRECT PORT: ${BASH_REMATCH[2]}, ACTION: ${BASH_REMATCH[3]}"
        fi
    done

    for LINE in "${LINES[@]}"; do
        if [[ "$LINE" =~ fh[[:space:]]+(1::8[0-9][0-9][[:space:]]).*match[[:space:]]([0-9a-f]{8}/[0-9a-f]{8}).*gact[[:space:]]action[[:space:]](.*)[[:space:]]random ]]; then
            log "${BASH_REMATCH[1]}\t TCP RESERVED PORT: ${BASH_REMATCH[2]}, ACTION: ${BASH_REMATCH[3]}"
        fi
    done

    for LINE in "${LINES[@]}"; do
        if [[ "$LINE" =~ fh[[:space:]]+(1::9[0-9][0-9]).*match[[:space:]]([0-9a-f]{8}/[0-9a-f]{8}).*mirred[[:space:]]\((.*)\) ]]; then
            log "${BASH_REMATCH[1]}\t TCP DYNAMIC PORT: ${BASH_REMATCH[2]}, ACTION: ${BASH_REMATCH[3]}"
        fi
    done

    for LINE in "${LINES[@]}"; do
        if [[ "$LINE" =~ fh[[:space:]]+(2::[0-9]?[0-9][[:space:]]|1::[1-7][0-9][0-9][[:space:]]).*match[[:space:]]([0-9a-f]{8}/[0-9a-f]{8}).*mirred[[:space:]]\((.*)\) ]]; then
            log "${BASH_REMATCH[1]}\t UDP REDIRECT PORT: ${BASH_REMATCH[2]}, ACTION: ${BASH_REMATCH[3]}"
        fi
    done

    for LINE in "${LINES[@]}"; do
        if [[ "$LINE" =~ fh[[:space:]]+(2::8[0-9][0-9][[:space:]]).*match[[:space:]]([0-9a-f]{8}/[0-9a-f]{8}).*gact[[:space:]]action[[:space:]](.*)[[:space:]]random ]]; then
            log "${BASH_REMATCH[1]}\t UDP RESERVED PORT: ${BASH_REMATCH[2]}, ACTION: ${BASH_REMATCH[3]}"
        fi
    done

    for LINE in "${LINES[@]}"; do
        if [[ "$LINE" =~ fh[[:space:]]+(2::9[0-9][0-9]).*match[[:space:]]([0-9a-f]{8}/[0-9a-f]{8}).*mirred[[:space:]]\((.*)\) ]]; then
            log "${BASH_REMATCH[1]}\t UDP DYNAMIC PORT: ${BASH_REMATCH[2]}, ACTION: ${BASH_REMATCH[3]}"
        fi
    done

    for LINE in "${LINES[@]}"; do
        if [[ "$LINE" =~ fh[[:space:]]+(3::[0-9]+[[:space:]]).*mirred[[:space:]]\((.*)\) ]]; then
            log "${BASH_REMATCH[1]}\t ICMP ACTION: ${BASH_REMATCH[2]}"
        fi
    done

   for LINE in "${LINES[@]}"; do
        if [[ "$LINE" =~ fh[[:space:]]+(4::[0-9]+[[:space:]]).*mirred[[:space:]]\((.*)\) ]]; then
            log "${BASH_REMATCH[1]}\t ARP ACTION: ${BASH_REMATCH[2]}"
        fi
    done







}

function check_link() {
    local LOGTAG="check-link"
    if [ ${#@} -ne 2 ]; then
        log "$LOGTAG: usage: check-link pai-sbx-ubuntu-1 ppp0" 
        exit 1
    fi
    log "$LOGTAG: nothing to do, args: $*"
}

function _type() {
    echo "$TYPE"
}

function help() {
    log "Usage: $0 <action> [action args...]"
    log "  $0 set-link-up <sandboxName> <link> eg: set-link-up pai-sbx-ubuntu-1 ppp0"
    log "  $0 set-link-down <sandboxName> <link>"
    log "  $0 check-link <sandboxName> <link>"
    log "  $0 expose-ports <sandboxName> <link> <port1> <port2> <port3> eg: expose-ports pai-sbx-ubuntu-1 ppp0 8080 8081 8082" 
    log ""
    exit 1
}

function version() {
    log "$VERSION"
}

function main() {
    ACTION=$1
    if [ -n "$ACTION" ]; then shift 1; fi
    case $ACTION in 
    "list")
        list "$@"
        ;;
    "add-box")
        add_box "$@"
        ;;
    "del-box")
        del_box "$@"
        ;;
    "set-link-up")
        create_box_link "$@"
        ;;
    "set-link-down")
        remove_box_link "$@"
        ;;
    "expose-ports")
        set_box_ports "$@"
        ;;
    "clear-device")
        clear_device_filter "$@"
        ;;
    "clear-host")
        clear_host "$@"
        ;;
    "check-link")
        check_link "$@"
        ;;
    "type")
        _type "$@"
        ;;
    "version")
        version "$@"
        ;;
    *) help ;;
    esac
}

main "$@"
