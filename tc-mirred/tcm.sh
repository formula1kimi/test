#!/bin/bash 
set -e -o pipefail

NAME_PREFIX="pai-box"
function log() {
    echo "$@" >&2
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

# arg1: boxid
# arg2: container name
# arg3: device
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

    local PORT_START
    PORT_START=$(start_port_byid "$IDX")
    local PORT_END
    PORT_END=$(end_port_byid "$IDX")
    local PORT_RANGE="$PORT_START $PORT_END"
    echo "Use Port Range: $PORT_RANGE"

    # veth device can be removed when container is removed
    if ip link show "$VETH" 2>/dev/null; then
        echo "Remove old vethpair: $VETH"
        ip link del "$VETH"
    fi
    echo "Create vethpair: $VETH <---> virtual $DEVICE"
    ip link add "$VETH" type veth peer name "$DEVICE" netns "$NETNS"
    echo "Setup container network interface: $VETH <---> virtual $DEVICE"
    nsenter -t "$NETNS" -n ip link set "$DEVICE"
    nsenter -t "$NETNS" -n ip addr add "$IPADDR" dev "$DEVICE"
    nsenter -t "$NETNS" -n ip link set dev "$DEVICE" address "$MACADDR"
    nsenter -t "$NETNS" -n ip link set "$DEVICE" up
    nsenter -t "$NETNS" -n ip route replace default via "$GW" dev "$DEVICE"
    nsenter -t "$NETNS" -n sysctl net.ipv4.ip_local_port_range="${PORT_RANGE/-/ }"
    nsenter -t "$NETNS" -n sysctl net.ipv4.icmp_echo_ignore_all=1
    nsenter -t "$NETNS" -n sysctl net.ipv4.conf.all.arp_ignore=8
    ip link set "$VETH" up

    # [net]<--[egress (Host Dev)]<--!!REDIRECT!!<--[(veth host)ingress]<--vlink<--[egress (veth peer)]<--[process]
    echo "Forward container ALL traffic from $CONTAINER to host $DEVICE"
    tc qdisc replace dev "$VETH" handle ffff: ingress
    tc filter replace dev "$VETH" parent ffff: protocol ip prio 1 u32 match u32 0 0 action mirred egress redirect dev "${DEVICE}"
    tc filter replace dev "$VETH" parent ffff: protocol arp u32 match u32 0 0 action mirred egress redirect dev "${DEVICE}"
    tc filter replace dev "$VETH" parent ffff: protocol ip prio 1 u32 match ip protocol 1 0xFF action mirred egress redirect dev "$DEVICE"

}   

function uninit_container_net() {
    local IDX=$1
    local CONTAINER=$2
    local DEVICE=$3
    local VETH="veth$IDX"
    echo "Veth host: $VETH"
        
    NETNS=$(docker inspect --format "{{.State.Pid}}" "${CONTAINER}")
    echo "NetNS: $NETNS"

    echo "Remove vethpair: $VETH <---> virtual $DEVICE"
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
        echo "Error, filter index for dynamic port forward exceed 999, abort"
        exit 1
    fi

    # [net]-->[ingress (Host Dev)]-->!!REDIRECT!!-->[(veth host)egress]-->vlink-->[ingress (veth peer) ]-->[process]
    echo "Forward Dynamic port range $PORT_RANGE to boxid $IDX"
    # Even use replace, must specify full handle id. 
    tc filter replace dev "$DEVICE" parent ffff: protocol ip prio 1 handle 1::$FIDX u32 ht 1: match tcp dst "$PORT_START" f000 action mirred egress redirect dev "$VETH"
    tc filter replace dev "$DEVICE" parent ffff: protocol ip prio 1 handle 2::$FIDX u32 ht 2: match udp dst "$PORT_START" f000 action mirred egress redirect dev "$VETH"
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
        echo "Error, filter index for dynamic port forward exceed 999, abort"
        exit 1
    fi
    echo "Remove forward dynamic port range $PORT_RANGE from boxid $IDX"
    tc filter del dev "$DEVICE" parent ffff: protocol ip prio 1 handle 1::$FIDX u32 || true
    tc filter del dev "$DEVICE" parent ffff: protocol ip prio 1 handle 2::$FIDX u32 || true
}

function add_arp_forward() {
    local IDX=$1
    local DEVICE=$2
    local VETH="veth$IDX"
    local FILTER_CONTINUE=$3
    echo "Add Mirror ARP to boxid: $IDX"
    # Even use replace, must specify full handle id. 
    tc filter replace dev "$DEVICE" parent ffff: protocol arp prio 4 handle 4::$IDX u32 ht 4: match u32 0 0 action mirred egress mirror dev "$VETH" $FILTER_CONTINUE
}

function remove_arp_forward() {
    local IDX=$1
    local DEVICE=$2
    local VETH="veth$IDX"
    echo "Remove Mirror ARP from boxid: $IDX"
    tc filter del dev "$DEVICE" parent ffff: protocol arp prio 4 handle 4::$IDX u32 || true
}

function add_icmp_forward() {
    local IDX=$1
    local DEVICE=$2
    local VETH="veth$IDX"
    local FILTER_CONTINUE=$3
    echo "Add Mirror ICMP to boxid: $IDX"
    # Even use replace, must specify full handle id. 
    tc filter replace dev "$DEVICE" parent ffff: protocol ip prio 1 handle 3::$IDX u32 ht 3: match u32 0 0 action mirred egress mirror dev "$VETH" $FILTER_CONTINUE
}

function remove_icmp_forward() {
    local IDX=$1
    local DEVICE=$2
    echo "Remove Mirror ICMP from boxid: $IDX"
    tc filter del dev "$DEVICE" parent ffff: protocol ip prio 1 handle 3::$IDX u32 || true
}

function add_static_port_forward() {
    local IDX=$1
    local CONTAINER=$2
    local DEVICE=$3
    VETH="veth$IDX"
    STATIC_PORTS=$4
    local STATIC_PORTS="${STATIC_PORTS/,/ }"

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
        echo "Error, filter index for static port forward exceed $FIDX_END, abort"
        exit 1
    fi


    for PORT in ${STATIC_PORTS}; do 
        echo "Mirror static port $PORT to container $CONTAINER" 
        if ! echo "$PORT" | grep -q -E '^[0-9]+$'; then
            echo "Bad port number: $PORT, skip"
            continue
        fi
        tc filter add dev "$DEVICE" parent ffff: protocol ip prio 1 handle 1::$FIDX u32 ht 1: match tcp dst "$PORT" 0xffff action mirred egress redirect dev "$VETH"
        tc filter add dev "$DEVICE" parent ffff: protocol ip prio 1 handle 2::$FIDX u32 ht 2: match udp dst "$PORT" 0xffff action mirred egress redirect dev "$VETH"
        FIDX=$((FIDX+1))
        if [ $FIDX -gt $FIDX_END ]; then
            echo "Error, filter index for static port forward exceed $FIDX_END, abort"
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
    log "Remove filter ids for staitc port forward: $FIDXS"
    for FIDX in $FIDXS; do 
        tc filter del dev "$DEVICE" ingress protocol ip pref 1 handle 1::$FIDX u32
        tc filter del dev "$DEVICE" ingress protocol ip pref 1 handle 2::$FIDX u32
    done

}

function init_host() {
    local DEVICE=$1

    if [ -z "$DEVICE" ]; then
        echo "Error: device is not specified"
        exit 1
    fi

    # Adjust port range to 32768,60999, which is default settings.
    sysctl net.ipv4.ip_local_port_range="32768 60999"

    # Build up the tc filter structure for all rules.
    init_filter_ht "$DEVICE"

    skip_host_port_redirect "$DEVICE"
}

function skip_host_port_redirect() {
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
        echo "Error, filter index for host port forward exceed 899, abort"
        exit 1
    fi
    echo "Host ports need skip redirect: $rule_ports"
    for PORT in $rule_ports; do 
        echo "skip redirect host port: $PORT" 
        if ! echo "$PORT" | grep -q -E '^[0-9]+$'; then
            echo "Bad port number: $PORT, skip"
            continue
        fi
        # Check duplication
        if tc filter show dev "$DEVICE" ingress protocol ip pref 1 | grep '1::8[0-9][0-9]' -A1 | grep -q $(printf "%08x/0000ffff" $PORT); then
            echo "  host port $PORT, already added rule"
            continue
        fi
 
        tc filter add dev "$DEVICE" parent ffff: protocol ip prio 1 handle 1::$FIDX u32 ht 1: match tcp dst "$PORT" 0xffff action ok
        tc filter add dev "$DEVICE" parent ffff: protocol ip prio 1 handle 2::$FIDX u32 ht 2: match udp dst "$PORT" 0xffff action ok
        FIDX=$((FIDX+1))
        if [ $FIDX -gt 899 ]; then
            echo "Error, filter index for host port forward exceed 899, abort"
            exit 1
        fi
    done
 
}

function init_filter_ht() {
    local DEVICE=$1
    if ! (tc qdisc show dev "$DEVICE" ingress | grep -q ingress); then
        echo "Create $DEVICE ingress qdisc"
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

}

function find_available_boxidx() {
    # find all box container, and their port range
    local containers
    containers="$(docker ps | grep "$NAME_PREFIX" | awk '{print $1}')"
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
        c_range=($(nsenter -t "$pid" -n sysctl -n net.ipv4.ip_local_port_range | awk '{print $1, $2}'))
        echo "Running sandbox: ${containers[*]}, port-range: ${c_range[*]}" >&2
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
    echo "Port Ranges: ${all_ranges[*]}" >&2
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
        echo "Usage: add-box <container name> <image> [ cmds/args... ]"
        echo "Example: add-box net ubuntu:20.04 tail -f /dev/null"
        exit 1
    fi
    shift 2

    if docker ps | grep -q "$NAME"; then
        echo "Error, container $NAME is already exist."
        exit 1;
    fi
    start_container "$NAME" "$IMAGE" $@
}

function init_box() {
    local NAME=$1
    local DEV=$2
    if [ -z "$DEV" ] || [ -z "$NAME" ] ; then
        help
    fi
 
    # Find a BOXID by prefix
    local BOXID
    BOXID=$(find_available_boxidx "$NAME")
    if [ -z "$BOXID" ]; then 
        echo "Can not find availble box id"
        exit 1
    fi

    echo "Using box idx: $BOXID for container: $NAME"
    init_container_net  "$BOXID" "$NAME" "$DEV" 
    add_dynamic_port_forward "$BOXID" "$DEV" 
    add_arp_forward "$BOXID" "$DEV" continue
    add_icmp_forward "$BOXID" "$DEV" continue
}

function uninit_box() {
    local NAME=$1
    local DEV=$2
    if [ -z "$DEV" ] || [ -z "$NAME" ] ; then
        help
    fi

    # Find a BOXID by prefix
    local BOXID
    BOXID=$(find_container_boxid "$NAME")
    if [ -z "$BOXID" ]; then
        echo "Error: Can not get boxid of container $NAME, make sure it's sandbox container"
        exit 1
    fi
 
    log "Container: $NAME box id = $BOXID"
    uninit_container_net "$BOXID" "$NAME" "$DEV"
    remove_dynamic_port_forward "$BOXID" "$DEV"
    remove_arp_forward "$BOXID" "$DEV"
    remove_icmp_forward "$BOXID" "$DEV"
    remove_static_port_forward "$BOXID" "$DEV"
}

function find_container_boxid() {
    local NAME=$1
    local CID
    CID="$(docker ps | grep "$NAME" | awk '{print $1}')"
    if [ -z "$CID" ]; then
        echo "Error: Can not find container" >&2
        return
    fi

    local pid
    pid=$(docker inspect --format "{{.State.Pid}}" "${NAME}")
    c_range=($(nsenter -t "$pid" -n sysctl -n net.ipv4.ip_local_port_range | awk '{print $1, $2}'))
    local idx
    idx=$(((c_range[0] - 8192) / 4096 + 1))
    echo $idx
}

function add_port() {
    local DEV=$1
    local PORTS=$2
    local NAME=$3
    if [ -z "$NAME" ] || [ -z "$DEV" ] || [ -z "$PORTS" ]; then
        echo "Usage: add-port <host dev> <ports> <container name>"
        echo "Example: add-port  eth0 3412,10456 net-1"
        exit 1
    fi
    local BOXID
    BOXID=$(find_container_boxid "$NAME")
    if [ -z "$BOXID" ]; then
        echo "Error: Can not get boxid of container $NAME, make sure it's sandbox container"
        exit 1
    fi
    echo "Add static port to $NAME with id: $BOXID"
    add_static_port_forward "$BOXID" "$NAME" "$DEV" "$PORTS"
}

#===========================================================
# interface function for integration with InstMgr
#===========================================================

# arg1: container name
# arg2: device name
function set_link_up() {
    local C=$1
    local DEV=$2
    init_box "$DEV" "$C"
}

# arg1: container name
# arg2: device name
function set_link_down() {
    local C=$1
    local DEV=$2
    uninit_box "$DEV" "$C"
}

function help() {
    log "Usage: $0 <action> [action args...]"
    log "  $0 set-link-up <sandboxName> <link> eg: set-link-up pai-sbx-ubuntu-1 ppp0"
    log "  $0 set-link-down <sandboxName> <link>"
    log "  $0 check-link <sandboxName> <link>"
    log "  $0 expose-ports <sandboxName> <link> <port1> <port2> <port3> eg: expose-ports pai-sbx-ubuntu-1 ppp0 8080 8081 8082" 
    log ""
    log "standalone action: "
    log "   init-host, add-box, init-box, add-port"
    exit 1
}

function main() {
    local ACTION=$1
    if [ -n "$ACTION" ]; then shift 1; fi
    case $ACTION in 
    "init-host")
        init_host "$@"
        ;;
    "add-box")
        add_box "$@"
        ;;
    "init-box")
        init_box "$@"
        ;;
    "add-port")
        add_port "$@"
        ;;
    "set-link-up")
        init_box "$@"
        ;;
    "set-link-down")
        uninit_box "$@"
        ;;
    "check-link")
        check_link "$@"
        ;;
    "expose-ports")
        expose_ports "$@"
        ;;
    "type")
        type "$@"
        ;;
    *) help ;;
    esac
}

main "$@"
