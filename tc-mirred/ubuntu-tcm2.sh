#!/bin/bash

# task infomation
TASK_NAME=ubuntu
VERSION=0
DEFAULT_IMAGE=ubuntu:20.04

DEFAULT_VOLUME_PATH=/storage # docker run -v /hostpath1:/storage1 -v /hostpath2:/storage2
STORAGE_MODE=M               # task storage mode: Z,S,M
NETWORK_MODE=M               # task network mode: Z,S,M
INSTANCE_MODE=M              # task instance mode: S,M
GRACEFUL_STOP_SECONDS=1      # how long to stop a instance gracefully
NEED_SOCKBIND=1              # depends on NETWORK_MODE==S, use libsockbind.so to bind instance to nic device
ALLOW_DOWN_IN_UP=0           # whether allow to bring stop an instance when bring it up.
STRICT_VOLUME_CHECK=${STRICT_VOLUME_CHECK:-0}
STRICT_DEVICE_CHECK=${STRICT_DEVICE_CHECK:-0}

# CONTAINER_RESTART_POLICY="always"

# CONTAINER_NETWORK_MODE="host"

# CONTAINER_NETWORK_MODE="ppy"
CONTAINER_PPY_ID=54 # https://www.paigod.work/meta/business

function handle_up() {
    local INST_ID=$1
    if [ $STORAGE_MODE == "M" ]; then
        # TODO handle multi storage on ${OPT_VOLUMES[@]}
        local INST_ID=0
        while [ $INST_ID -lt ${#OPT_VOLUMES[@]} ]; do
            if [ "${OPT_VOLUMES[$INST_ID]}" != "$STORAGE_PLACEHOLDER" ]; then
                CMD="$CMD -v ${OPT_VOLUMES[$INST_ID]}:${DEFAULT_VOLUME_PATH}$(($INST_ID + 1))"
            fi
            INST_ID=$(($INST_ID + 1))
        done
    elif [ $STORAGE_MODE == "S" ]; then
        # TODO handle single storage on $OPT_VOLUMES
        CMD="$CMD -v $OPT_VOLUMES:$DEFAULT_VOLUME_PATH"
    fi

    # if [ $NETWORK_MODE == "M" ]; then
    # TODO handle multi line on ${OPT_DEVICES[@]}
    # elif [ $NETWORK_MODE == "S" ]; then
    # TODO handle single line  on $OPT_DEVICES
    if [ "$CONTAINER_NETWORK_MODE" == "ppy" ]; then
        local NICID=$(echo $OPT_DEVICES | grep -Eo "[0-9]*")
        if [ "$NICID" != "" ]; then
            ensure_bridge $CONTAINER_PPY_ID
            local NETWORK_ARGS="--network=ppy$CONTAINER_PPY_ID --ip 172.20.${CONTAINER_PPY_ID}.$(expr 2 + $NICID)"
            CMD="$CMD $NETWORK_ARGS"
        else
            local NETWORK_ARGS="--network=bridge" # fallback to bridge mode
            CMD="$CMD $NETWORK_ARGS"
        fi
    fi
    # fi

    # TODO handle extras on ${OPT_EXTRAS[@]}
    # for EXTRA in "${OPT_EXTRAS[@]}"; do
    #     if [ $(echo "$EXTRA" | grep "^SOME_KEY=" | wc -l) -eq 1 ]; then
    #         ...
    #     fi
    # done

    # TODO handle other envs or anything else
    # CMD="$CMD -e CUSTOMER_ID=ppio"
}

function handle_mutate() {
    # local EXTRAS=()
    # if [ "$(echo "$NODE_INFO" | jq '.network.public // empty' -r)" == "false" ]; then
    #   EXTRAS+=("nat=1")
    # fi
    # join_by "$JOIN_DELIMITER" "${EXTRAS[@]}"
    :
}

# --------------------------------------------

# instance manager version
TEMPLATE_VERSION=20

# internal envs, please DO NOT modify it.
DEFAULT_DEVICES_ENV_NAME=PAI_DEVICES # docker run -e PAI_DEVICES=ppp0,ppp1,ppp2,...
DEFAULT_VOLUMES_ENV_NAME=PAI_VOLUMES # docker run -e PAI_VOLUMES=/hostpath1,/hostpath2,...
DEFAULT_EXTRAS_ENV_NAME=PAI_EXTRAS   # docker run -e PAI_EXTRAS=key1=val1,key2=val2,...
JOIN_DELIMITER=$(echo -en '\x03')
ENTRY_DELIMITER=$(echo -en '\x04')
DEFAULT_PAI_NETWORK_MANAGER_ENV_NAME=PAI_NETWORK_MANAGER
DEFAULT_PAI_NETWORK_EXPOSE_PORTS_ENV_NAME=PAI_NETWORK_EXPOSE_PORTS
DEFAULT_NETWORK_MANAGER_DOWNLOAD_PATH="https://pi-ops.oss-cn-hangzhou.aliyuncs.com/k8s/network"
DEFAULT_SANDBOX_IMAGE=registry.cn-hangzhou.aliyuncs.com/google_containers/pause:3.2
DEFAULT_NETWORK_MANAGER_PATH=/opt/tasknetes/network
STORAGE_PLACEHOLDER="-"

# for test image, override ARGS
if [ "${DEFAULT_IMAGE%:*}" == "ubuntu" ] || [ "${DEFAULT_IMAGE%:*}" == "centos" ]; then
    if [ "$DEFAULT_ARGS" == "" ]; then
        DEFAULT_ARGS="tail -f /dev/null >/dev/null"
    fi
fi

function ensure_bridge() {
    local TASK_ID=$1
    if [ $(docker network ls | awk '{print $2}' | grep ppy$TASK_ID | wc -l) -eq 0 ]; then
        local MTU=1500
        if [ $(cat /sys/class/net/ppp*/mtu 2>/dev/null | sort | uniq | wc -l) -gt 0 ]; then
            MTU=$(cat /sys/class/net/ppp*/mtu 2>/dev/null | sort | uniq | head -1)
        fi
        local NETWORK_ID=$TASK_ID
        docker network create --driver bridge --subnet=172.20.${NETWORK_ID}.0/24 --gateway=172.20.${NETWORK_ID}.1 \
            --opt com.docker.network.driver.mtu=$MTU --opt com.docker.network.bridge.name=ppy${NETWORK_ID} ppy${NETWORK_ID} 1>&2
    fi
}

function all_volumes_ready() {
    local OPT_VOLUMES=${@}
    for VOLUME in ${OPT_VOLUMES[@]}; do
        if touch "$VOLUME/.test" 2>&1 | grep 'Input/output error' &>/dev/null; then
            echo "$LOGTAG: failed to writing test file in mountpoint"
            exit 1
        fi
        rm "$VOLUME/.test"
    done
}

function join_by() {
    local d=${1-} f=${2-}
    if shift 2; then printf %s "$f" "${@/#/$d}"; fi
}

function get_sandbox_key() {
    local SANDBOX_ID=$1
    local INSPECT_DATA
    if INSPECT_DATA=$(docker inspect $SANDBOX_ID 2>/dev/null); then
        local SANDBOX_KEY
        if ! SANDBOX_KEY=$(echo "$INSPECT_DATA" | jq -r '.[].NetworkSettings.SandboxKey'); then
            echo "$LOGTAG: failed to get sandboxKey in exists container $SANDBOX_ID" >&2
            exit 1
        fi

        echo "$SANDBOX_KEY"
        return 0
    fi
    return 1
}

function try_download_network_manager() {
    local NETWORK_MANAGER=$1
    if [ -z "$NETWORK_MANAGER" ] || [ -z "$EXEC_PATH" ]; then
        echo "$LOGTAG: missing NETWORK_MANAGER or EXEC_PATH" >&2
        exit 1
    fi

    local DOWNLOAD_PATH="${NETWORK_MANAGER_DOWNLOAD_PATH:-$DEFAULT_NETWORK_MANAGER_DOWNLOAD_PATH}/${NETWORK_MANAGER}"
    echo "$LOGTAG: downloading $DOWNLOAD_PATH to $EXEC_PATH" >&2
    if ! curl -L -s $DOWNLOAD_PATH -o $EXEC_PATH; then
        echo "$LOGTAG: failed to download $DOWNLOAD_PATH to $EXEC_PATH" >&2
        rm -f $EXEC_PATH
        exit 1
    fi
    chmod +x $EXEC_PATH
}

function teardown_sandbox() {
    local SANDBOX_ID=$1

    # in teardown stage, need retrieve DEVICES and NETWORK_MANAGER from container env...
    local DEVICES=()
    local SANDBOX_ENV_DATA
    local NETWORK_MANAGER
    if ! SANDBOX_ENV_DATA=$(docker inspect $SANDBOX_ID | jq -r '.[].Config.Env[]'); then
        echo "$LOGTAG: failed to inspect sandbox env data" >&2
        exit 1
    fi
    DEVICES=($(echo "$SANDBOX_ENV_DATA" | grep PAI_DEVICES | sed 's|PAI_DEVICES=||' | tr -s "," '\n'))
    NETWORK_MANAGER=$(echo "$SANDBOX_ENV_DATA" | grep "^$DEFAULT_PAI_NETWORK_MANAGER_ENV_NAME" | sed "s|$DEFAULT_PAI_NETWORK_MANAGER_ENV_NAME=||")

    if [ -n "$NETWORK_MANAGER" ] && [ -n "$SANDBOX_ID" ]; then
        local EXEC_PATH="${NETWORK_MANAGER_PATH:-$DEFAULT_NETWORK_MANAGER_PATH}/$NETWORK_MANAGER"
        if [ ! -f "$EXEC_PATH" ]; then
            try_download_network_manager $NETWORK_MANAGER
        fi

        if [ ! -f "$EXEC_PATH" ] || [ ! -r "$EXEC_PATH" ] || [ ! -x "$EXEC_PATH" ]; then
            echo "$LOGTAG: failed to exec network manager: $NETWORK_MANAGER in $EXEC_PATH" >&2
            exit 1
        fi

        if [ ${#DEVICES[@]} -eq 0 ]; then
            echo "$LOGTAG: set-link-down $SANDBOX_ID ALL" >&2
            $EXEC_PATH set-link-down $SANDBOX_ID "ALL" >&2
        else
            for DEVICE in ${DEVICES[@]}; do
                echo "$LOGTAG: set-link-down $SANDBOX_ID $DEVICE" >&2
                $EXEC_PATH set-link-down $SANDBOX_ID $DEVICE >&2
            done
        fi

        echo "$LOGTAG: remove_sandbox, docker rm $SANDBOX_ID" >&2
        docker rm -f "$SANDBOX_ID" 1>&2
    fi
}

function setup_sandbox() {
    local LOGTAG=setup_sandbox
    local INST_ID=$1
    if [ -z "$INST_ID" ]; then
        echo "$LOGTAG: missing INST_ID" >&2
        exit 1
    fi

    if [ -z "$OPT_NETWORK_MANAGER" ]; then
        echo "$LOGTAG: missing NETWORK_MANAGER" >&2
        exit 1
    fi

    local INSPECT_DATA
    local SANDBOX_KEY
    local SANDBOX_ID="pai-box-$TASK_NAME-$INST_ID"

    local EXEC_PATH="${NETWORK_MANAGER_PATH:-$DEFAULT_NETWORK_MANAGER_PATH}/$OPT_NETWORK_MANAGER"
    if [ ! -f "$EXEC_PATH" ]; then
        try_download_network_manager $OPT_NETWORK_MANAGER
    fi

    if [ ! -f "$EXEC_PATH" ] || [ ! -r "$EXEC_PATH" ] || [ ! -x "$EXEC_PATH" ]; then
        echo "$LOGTAG: failed to exec network manager: $OPT_NETWORK_MANAGER in $EXEC_PATH" >&2
        exit 1
    fi

    # if the sandbox container already exists should keep it
    if SANDBOX_KEY=$(get_sandbox_key $SANDBOX_ID); then
        echo "$SANDBOX_ID"
    fi

    local DEVICES
    if [ ${#OPT_DEVICES[@]} -eq 0 ]; then
        DEVICES="ALL"
    else
        DEVICES=$(join_by "," "${OPT_DEVICES[@]}")
    fi

    if ! CID=$(docker run -tid --privileged -v /etc/localtime:/etc/localtime:ro --log-opt max-size=20m --log-opt max-file=5 \
        --network=none \
        --restart=always \
        --name $SANDBOX_ID \
        --env $DEFAULT_PAI_NETWORK_MANAGER_ENV_NAME=$OPT_NETWORK_MANAGER \
        --env $DEFAULT_DEVICES_ENV_NAME="$DEVICES" \
        --env $DEFAULT_PAI_NETWORK_EXPOSE_PORTS_ENV_NAME=$(join_by "," ${CONTAINER_EXPOSE_PORTS[@]}) \
        ${SANDBOX_IMAGE:-$DEFAULT_SANDBOX_IMAGE}); then
        echo "$LOGTAG: failed to start sandbox container" >&2
        exit 1
    fi

    if [ $NETWORK_MODE == "Z" ] && [ "$CONTAINER_NETWORK_MODE" != "ppy" ]; then
        echo "$LOGTAG: set-link-up $SANDBOX_ID ALL" >&2
        if ! $EXEC_PATH set-link-up $SANDBOX_ID "ALL" >&2; then
            # if fail, remove sandbox
            docker rm -f $SANDBOX_ID &>/dev/null
            echo "$LOGTAG: failed to set-link-up $SANDBOX_ID ALL" >&2
            exit 1
        fi
        if [ -n "$CONTAINER_EXPOSE_PORTS" ] && [ "${#CONTAINER_EXPOSE_PORTS}" -gt 0 ]; then
            for PORT in ${CONTAINER_EXPOSE_PORTS[@]}; do
                echo "$LOGTAG: expose-ports $SANDBOX_ID ALL $PORT" >&2
                if ! $EXEC_PATH expose-ports $SANDBOX_ID "ALL" $PORT >&2; then
                    # if fail, remove sandbox
                    docker rm -f $SANDBOX_ID &>/dev/null
                    echo "$LOGTAG: failed to expose-ports $SANDBOX_ID ALL $PORT" >&2
                    exit 1
                fi
            done
        fi
    else
        for DEVICE in ${OPT_DEVICES[@]}; do
            echo "$LOGTAG: set-link-up $SANDBOX_ID $DEVICE" >&2
            if ! $EXEC_PATH set-link-up $SANDBOX_ID $DEVICE >&2; then
                # if fail, remove sandbox
                docker rm -f $SANDBOX_ID &>/dev/null
                echo "$LOGTAG: failed to set-link-up $SANDBOX_ID $DEVICE" >&2
                exit 1
            fi
            if [ -n "$CONTAINER_EXPOSE_PORTS" ] && [ "${#CONTAINER_EXPOSE_PORTS}" -gt 0 ]; then
                echo "$LOGTAG: expose-ports $SANDBOX_ID $PORT" >&2
                for PORT in ${CONTAINER_EXPOSE_PORTS[@]}; do
                    if ! $EXEC_PATH expose-ports $SANDBOX_ID $DEVICE $PORT >&2; then
                        # if fail, remove sandbox
                        docker rm -f $SANDBOX_ID &>/dev/null
                        echo "$LOGTAG: failed to expose-ports $SANDBOX_ID ALL $PORT" >&2
                        exit 1
                    fi
                done
            fi
        done
    fi

    echo "$SANDBOX_ID"
}

# start -v volume -l dev -e image=ubuntu:20.04
function start() {
    local LOGTAG=start
    local OPTIND ignore
    local OPT_VOLUMES=()
    local OPT_DEVICES=()
    local OPT_EXTRAS=()
    local OPT_EXTRA_IMAGE=$DEFAULT_IMAGE
    local OPT_NETWORK_MANAGER
    local USE_DEFALT_IMAGE=1
    while getopts "v:l:e:h" opt; do
        case $opt in
        v)
            OPT_VOLUMES+=("$OPTARG")
            if [ $STORAGE_MODE == "S" ] && [ ${#OPT_VOLUMES[@]} -gt 1 ]; then
                echo "$LOGTAG: single storage mode task only supports one volume" >&2
                exit 1
            fi
            if [ $STORAGE_MODE == "Z" ] && [ ${#OPT_VOLUMES[@]} -gt 0 ]; then
                echo "$LOGTAG: zero storage mode task doesn't support volume" >&2
                exit 1
            fi
            ;;
        l)
            OPT_DEVICES+=("$OPTARG")
            if [ $NETWORK_MODE == "S" ] && [ "${#OPT_DEVICES[@]}" -gt 1 ]; then
                echo "$LOGTAG: signle line mode task only supports one device" >&2
                exit 1
            fi
            if [ $NETWORK_MODE == "Z" ] && [ ${#OPT_DEVICES[@]} -gt 0 ]; then
                echo "$LOGTAG: zero line mode task doesn't support device" >&2
                exit 1
            fi
            ;;
        e)
            OPT_EXTRAS+=("$OPTARG")
            if [ $(echo $OPTARG | grep '^image=' | wc -l) -eq 1 ]; then
                OPT_EXTRA_IMAGE=$(echo $OPTARG | sed 's/^image=//')
                USE_DEFALT_IMAGE=0
            fi

            if [ $(echo $OPTARG | grep "^pai_network_manager" | wc -l) -eq 1 ]; then
                OPT_NETWORK_MANAGER=$(echo $OPTARG | sed "s/^pai_network_manager=//")
                if [ "$OPT_NETWORK_MANAGER" == "none" ]; then
                    OPT_NETWORK_MANAGER=
                fi
            fi
            ;;
        h)
            echo "usage: up <-v /path/to/volume> <-l nic-dev> [-e image=${TASK_NAME}-image-uri]" >&2
            exit 1
            ;;
        \?)
            echo "$LOGTAG: invalid option $opt" >&2
            exit 1
            ;;
        esac
    done
    shift $(($OPTIND - 1))

    if [ $USE_DEFALT_IMAGE -eq 1 ]; then
        OPT_EXTRAS+=("image=$OPT_EXTRA_IMAGE")
    fi

    IFS2=$IFS
    IFS=$'\n'
    OPT_EXTRAS=($(for EXTRA in "${OPT_EXTRAS[@]}"; do
        echo "$EXTRA"
    done | sort))
    IFS=$IFS2

    local INST_ID=$1

    if [ $INSTANCE_MODE == "S" ]; then
        INST_ID=1
    fi

    echo "$LOGTAG: OPT_VOLUMES:${OPT_VOLUMES[@]} OPT_DEVICES:${OPT_DEVICES[@]} OPT_EXTRA_IMAGE:$OPT_EXTRA_IMAGE OPT_EXTRAS:${OPT_EXTRAS[@]}" >&2

    if [ $STORAGE_MODE == "S" ] || [ $STORAGE_MODE == "M" ]; then
        if [ ${#OPT_VOLUMES[@]} -eq 0 ]; then
            echo "$LOGTAG: volume is missing" >&2
            exit 1
        fi

        if [ "$STRICT_VOLUME_CHECK" == 1 ]; then
            local MOUNTS=$(cat /proc/mounts | awk '{print $2}' | grep -v "^/run" | grep -v "^/sys" | grep -v "^/$" | grep -v "^/boot" | grep -v "^/dev" | grep -v "^/proc")
            for TMP_VOLUME in ${OPT_VOLUMES[@]}; do
                local HIT=0
                for MOUNT in $MOUNTS; do
                    if [ $(echo $TMP_VOLUME | grep "^$MOUNT$" | wc -l) -gt 0 ] || [ $(echo $TMP_VOLUME | grep "^$MOUNT/" | wc -l) -gt 0 ]; then
                        HIT=1
                        break
                    fi
                done
                if [ $HIT -eq 0 ] && [ $(echo $TMP_VOLUME | grep "^/dev/" | wc -l) -eq 0 ]; then
                    echo "$LOGTAG: volume $TMP_VOLUME is not mounted" >&2
                    exit 1
                fi
            done

            all_volumes_ready ${OPT_VOLUMES[@]}
        fi
    fi

    if [ $NETWORK_MODE == "S" ] || [ $NETWORK_MODE == "M" ]; then
        if [ ${#OPT_DEVICES[@]} -eq 0 ]; then
            echo "$LOGTAG: device is missing" >&2
            exit 1
        fi

        if [ "$STRICT_DEVICE_CHECK" == 1 ]; then
            for TMP_DEVICE in ${OPT_DEVICES[@]}; do
                if ! ip link show dev $TMP_DEVICE &>/dev/null; then
                    echo "$LOGTAG: device $TMP_DEVICE doesn't exist" >&2
                    exit 1
                fi
            done
        fi
    fi

    local NEED_UP=0
    if [ "$INST_ID" == "" ]; then
        # let's try to find a inst id
        local CONTAINER_NAMES=$(docker ps -a --format '{{.Names}}')
        local INST_ID=1
        while [ $(echo "$CONTAINER_NAMES" | grep "^pai-$TASK_NAME-$INST_ID$" | wc -l) -gt 0 ]; do
            INST_ID=$(($INST_ID + 1))
        done
        NEED_UP=1
    else
        # check whether the instance exists.
        if [ $(docker ps -a --format '{{.Names}}' | grep "^pai-$TASK_NAME-$INST_ID$" | wc -l) -gt 0 ]; then
            local INSPECT_DATA=$(docker inspect pai-$TASK_NAME-$INST_ID)

            # HostConfig.Binds may be null.
            # local VOLUMES
            # if [ $(echo "$INSPECT_DATA" | grep '"Binds": null' | wc -l) -eq 0 ]; then
            #     VOLUMES=($(echo "$INSPECT_DATA" | jq -r '.[0].HostConfig.Binds[]' | grep ":$DEFAULT_VOLUME_PATH" | awk -F : '{print $1}'))
            # else
            #     VOLUMES=()
            # fi
            local VOLUMES=$(echo "$INSPECT_DATA" | jq -r '.[0].Config.Env[]' | grep "^$DEFAULT_VOLUMES_ENV_NAME=" | sed "s|^$DEFAULT_VOLUMES_ENV_NAME=||")
            local DEVICES=$(echo "$INSPECT_DATA" | jq -r '.[0].Config.Env[]' | grep "^$DEFAULT_DEVICES_ENV_NAME=" | sed "s|^$DEFAULT_DEVICES_ENV_NAME=||")
            local EXTRAS=$(echo "$INSPECT_DATA" | jq -r '.[0].Config.Env[]' | grep "^$DEFAULT_EXTRAS_ENV_NAME=" | sed "s|^$DEFAULT_EXTRAS_ENV_NAME=||")
            local IMAGE=$(echo "$INSPECT_DATA" | jq -r '.[0].Config.Image')
            local RUNNING=$(echo "$INSPECT_DATA" | jq -r '.[0].State.Running')

            echo "$LOGTAG: VOLUMES:${VOLUMES} DEVICES:${DEVICES} IMAGE:$IMAGE EXTRAS:$EXTRAS RUNNING:$RUNNING" >&2

            local NEED_DOWN=0
            while true; do
                # check whether volumes(hostpaths) change
                if [ "$(join_by "$JOIN_DELIMITER" "${OPT_VOLUMES[@]}")" != "$VOLUMES" ]; then
                    NEED_DOWN=1
                    break
                fi

                # check whether lines change
                if [ "$(join_by "$JOIN_DELIMITER" "${OPT_DEVICES[@]}")" != "$DEVICES" ]; then
                    NEED_DOWN=1
                    break
                fi

                # check whether extras change
                if [ "$(join_by "$JOIN_DELIMITER" "${OPT_EXTRAS[@]}")" != "$EXTRAS" ]; then
                    NEED_DOWN=1
                    break
                fi

                # check whether image change
                if [ "$IMAGE" != "$OPT_EXTRA_IMAGE" ]; then
                    NEED_DOWN=1
                    break
                fi

                break
            done

            if [ $NEED_DOWN -eq 1 ]; then
                if [ $ALLOW_DOWN_IN_UP -eq 1 ]; then
                    echo "$LOGTAG: bringing stop inst $INST_ID" >&2
                    stop $INST_ID
                    NEED_UP=1
                else
                    echo "$LOGTAG: need to bring stop inst $INST_ID first" >&2
                fi
            elif [ "$RUNNING" != "true" ]; then
                echo "$LOGTAG: docker start pai-$TASK_NAME-$INST_ID" >&2
                docker start pai-$TASK_NAME-$INST_ID &>/dev/null
                local RET=$?
                if [ $RET -eq 0 ]; then
                    echo $INST_ID
                fi
                return $RET
            else
                echo $INST_ID
                return 0
            fi
        else
            NEED_UP=1
        fi
    fi

    if [ $NEED_UP -eq 1 ]; then
        echo "$LOGTAG: docker run pai-$TASK_NAME-$INST_ID" >&2
        local CMD="docker run -d --privileged -v /etc/localtime:/etc/localtime:ro --log-opt max-size=20m --log-opt max-file=5"

        # ===========================================================
        handle_up $INST_ID
        # ===========================================================

        if [ -n "$OPT_NETWORK_MANAGER" ] && [ "$CONTAINER_NETWORK_MODE" != "ppy" ]; then
            local SANDBOX_ID
            if ! SANDBOX_ID=$(setup_sandbox $INST_ID); then
                echo "$LOGTAG: failed to setup sandbox $INST_ID" >&2
                exit 1
            fi

            CMD="$CMD --network container:$SANDBOX_ID"
        else
            if [ "$CONTAINER_NETWORK_MODE" == "host" ] || [ "$CONTAINER_NETWORK_MODE" == "" ]; then
                CMD="$CMD --network host"
            fi
        fi

        if [ "$CONTAINER_RESTART_POLICY" == "always" ] || [ "$CONTAINER_RESTART_POLICY" == "" ]; then
            CMD="$CMD --restart always"
        else
            CMD="$CMD --restart $CONTAINER_RESTART_POLICY"
        fi

        if [ $NETWORK_MODE == "S" ] && [ $NEED_SOCKBIND -eq 1 ]; then
            CMD="$CMD -e LD_PRELOAD=/lib/libsockbind.so -e LIBSOCKBIND_DEVICE=$OPT_DEVICES"
        fi
        CMD="$CMD -e $DEFAULT_VOLUMES_ENV_NAME=$(join_by "$JOIN_DELIMITER" "${OPT_VOLUMES[@]}")"
        CMD="$CMD -e $DEFAULT_DEVICES_ENV_NAME=$(join_by "$JOIN_DELIMITER" "${OPT_DEVICES[@]}")"
        CMD="$CMD -e $DEFAULT_EXTRAS_ENV_NAME="'"$(join_by "$JOIN_DELIMITER" "${OPT_EXTRAS[@]}")"'""
        CMD="$CMD -e PAI_TASK_NAME=pai-$TASK_NAME-$INST_ID --name pai-$TASK_NAME-$INST_ID $OPT_EXTRA_IMAGE $DEFAULT_ARGS"
        echo "$LOGTAG: $CMD" >&2
        eval $CMD 1>&2
        if [ $? -eq 0 ]; then
            echo $INST_ID
        fi
    fi
}

# update -r cpuShares=1000 -r memory=5120000 1
function update() {
    local LOGTAG=update
    local OPTIND ignore
    local OPT_RUNTIME=()

    while getopts "r:h" opt; do
        case $opt in
        r)
            OPT_RUNTIME+=("$OPTARG")
            ;;
        h)
            echo "usage: update [-e cpuShares=1000 ...] <id>" >&2
            exit 1
            ;;
        \?)
            echo "$LOGTAG: invalid option $opt" >&2
            exit 1
            ;;
        esac
    done
    shift $(($OPTIND - 1))

    local INST_ID=$1

    if [ -z "$INST_ID" ]; then
        echo "$LOGTAG: inst-id is missing" >&2
        exit 1
    fi

    local UPDATE_OPTS=""

    for RUNTIME in "${OPT_RUNTIME[@]}"; do
        IFS="=" read -ra KV <<<"$RUNTIME"
        if [ ${#KV[@]} -ne 2 ]; then
            echo "$LOGTAG: OPT_RUNTIME $RUNTIME invalid" >&2
            exit 1
        fi
        K=${KV[0]}
        V=${KV[1]}
        case $K in
        cpu-shares)
            UPDATE_OPTS="$UPDATE_OPTS --cpu-shares $V"
            ;;
        cpus)
            UPDATE_OPTS="$UPDATE_OPTS --cpus $V"
            ;;
        cpuset-cpus)
            UPDATE_OPTS="$UPDATE_OPTS --cpuset-cpus $V"
            ;;
        cpu-period)
            UPDATE_OPTS="$UPDATE_OPTS --cpu-period $V"
            ;;
        cpu-quota)
            UPDATE_OPTS="$UPDATE_OPTS --cpu-quota $V"
            ;;
        memory)
            UPDATE_OPTS="$UPDATE_OPTS --memory $V --memory-swap=-1"
            ;;
        *)
            echo "$LOGTAG: invalid option $K=$V" >&2
            exit 1
            ;;
        esac
    done

    echo "$LOGTAG: docker update pai-$TASK_NAME-$INST_ID $UPDATE_OPTS" >&2
    if ! docker update "pai-$TASK_NAME-$INST_ID" $UPDATE_OPTS >/dev/null; then
        echo "$LOGTAG: update failed" >&2
        exit 1
    fi
}

function stop() {
    local LOGTAG=stop
    local INST_ID=$1

    if [ $INSTANCE_MODE == "S" ]; then
        INST_ID=1
    fi

    if [ "$INST_ID" == "" ]; then
        echo "$LOGTAG: inst-id is missing" >&2
        exit 1
    fi

    local SANDBOX_ID=pai-$TASK_NAME-$INST_ID
    local INSPECT_DATA
    local SANDBOX_ID

    if ! INSPECT_DATA="$(docker inspect $SANDBOX_ID 2>/dev/null)"; then
        echo "$LOGTAG: failed to inspect $SANDBOX_ID" >&2
        exit 0 # TODO
    fi

    if [ ${GRACEFUL_STOP_SECONDS} -gt 0 ]; then
        echo "$LOGTAG: docker stop -t ${GRACEFUL_STOP_SECONDS} $SANDBOX_ID" >&2
        docker stop -t ${GRACEFUL_STOP_SECONDS} $SANDBOX_ID &>/dev/null
    fi

    SANDBOX_ID=$(echo "$INSPECT_DATA" | jq -r '.[].HostConfig.NetworkMode' | awk -F':' '($1=="container"){print $2}')
    if [ -n "$SANDBOX_ID" ]; then
        teardown_sandbox $SANDBOX_ID 1>&2
    fi

    echo "$LOGTAG: docker rm $SANDBOX_ID" >&2
    docker rm -f $SANDBOX_ID &>/dev/null
}

function list() {
    local LOGTAG=list

    # invisible delimiter
    local LINE_DELIMITER=$(echo -en '\x01')
    local SUB_DELIMITER=$(echo -en '\x02')
    local JQ_SCRIPTS='
    .[]| {
        name: .Name,
        image: .Config.Image,
        volumes: .HostConfig.Binds| join("'"$SUB_DELIMITER"'"),
        env: .Config.Env| join("'"$SUB_DELIMITER"'"),
        status: .State.Status,
        runtime: .HostConfig |  [
            "cpu-shares=" + (.CpuShares|tostring),
            "cpus=" + ((.NanoCpus / 1000000000) |tostring),
            "cpuset-cpus=" + (.CpusetCpus|tostring),
            "cpu-period=" + (.CpuPeriod|tostring),
            "cpu-quota=" + (.CpuQuota|tostring),
            "memory=" + (.Memory|tostring)
            ] | join ("'"$SUB_DELIMITER"'")
    } | join ("'"$LINE_DELIMITER"'")
    '

    CONTAINERS=($(docker ps --format="{{.Names}}" | grep "^pai-$TASK_NAME-" | sort -V))
    if [ "${#CONTAINERS[@]}" -eq 0 ]; then
        return 0
    fi

    IFS2=$IFS
    IFS=$'\n'
    if ! INSPECT_DATA=($(docker inspect "${CONTAINERS[@]}" | jq -r "$JQ_SCRIPTS")); then
        echo "$LOGTAG: inspect failed" >&2
        exit 1
    fi
    IFS=$IFS2

    for DATA in "${INSPECT_DATA[@]}"; do
        # eg: <name>|<image>|<binds>|<envs>|status
        # BIND_VOLUMES="$(echo "$DATA" | awk -F"$LINE_DELIMITER" '{print $3}' | tr -s "$SUB_DELIMITER" "\n")"
        STATUS=$(echo "$DATA" | awk -F"$LINE_DELIMITER" '{print $5}')
        RUNTIMES=$(echo "$DATA" | awk -F"$LINE_DELIMITER" '{print $6}' | tr -s "$SUB_DELIMITER" "\n")
        ENVS="$(echo "$DATA" | awk -F"$LINE_DELIMITER" '{print $4}' | tr -s "$SUB_DELIMITER" "\n")"

        local VOLUMES=$(echo "$ENVS" | grep "^$DEFAULT_VOLUMES_ENV_NAME=" | sed "s|^$DEFAULT_VOLUMES_ENV_NAME=||")
        local DEVICES=$(echo "$ENVS" | grep "^$DEFAULT_DEVICES_ENV_NAME=" | sed "s|^$DEFAULT_DEVICES_ENV_NAME=||")
        local EXTRAS=$(echo "$ENVS" | grep "^$DEFAULT_EXTRAS_ENV_NAME=" | sed "s|^$DEFAULT_EXTRAS_ENV_NAME=||")
        local STATES=()

        local IMAGE=$(echo "$DATA" | awk -F"$LINE_DELIMITER" '{print $2}')
        local ID=$(echo "$DATA" | awk -F"$LINE_DELIMITER" '{print $1}' | sed "s/^\/pai-$TASK_NAME-//")

        IFS2=$IFS
        IFS=$'\n'
        EXTRAS=($(echo "$EXTRAS" | tr "$JOIN_DELIMITER" "\n" | grep -v "^image="))
        EXTRAS=$(join_by $JOIN_DELIMITER "${EXTRAS[@]}")
        EXTRAS=$(join_by "$JOIN_DELIMITER" $(for EXTRA in "${EXTRAS[@]}" "image=$IMAGE"; do
            echo "$EXTRA"
        done | sort))

        RUNTIME=($(echo "$RUNTIME" | tr "$JOIN_DELIMITER" "\n"))
        RUNTIME=$(join_by $JOIN_DELIMITER "${RUNTIME[@]}")

        RUNTIME=$(join_by "$JOIN_DELIMITER" $(for RUNTIME in "${RUNTIMES[@]}"; do
            echo "$RUNTIME"
        done | sort))

        STATES=($(echo "$STATES" | tr "$JOIN_DELIMITER" "\n" | grep -v "^status="))
        STATES=$(join_by $JOIN_DELIMITER "${STATES[@]}")
        STATES=$(join_by "$JOIN_DELIMITER" $(for STATE in "${STATES[@]}" "status=$STATUS"; do
            echo "$STATE"
        done | sort))
        IFS=$IFS2
        # calling custimzed extras list handler
        type handle_list &>/dev/null && handle_list

        local OUT="$ID"
        OUT+=$ENTRY_DELIMITER
        OUT+=$VOLUMES
        OUT+=$ENTRY_DELIMITER
        OUT+=$DEVICES
        OUT+=$ENTRY_DELIMITER
        OUT+=$EXTRAS
        OUT+=$ENTRY_DELIMITER
        OUT+=$RUNTIME
        OUT+=$ENTRY_DELIMITER
        OUT+=$STATES
        echo "$OUT"
    done
}

function mutate() {
    local LOGTAG=mutate
    local NODE_INFO
    if ! NODE_INFO=$(echo "$1" | jq); then
        echo "$LOGTAG: invalid node info" >&2
        exit 1
    fi
    handle_mutate
}

function uninstall() {
    local LOGTAG="uninstall"
    IDS=$(docker ps -a --format '{{.Names}}' | grep "^pai-$TASK_NAME-")
    for ID in $IDS; do
        docker rm -f $ID &>/dev/null
    done

    SANDBOX_NAMES=$(docker ps -a --format '{{.Names}}' | grep "^pai-box-$TASK_NAME-")
    for SANDBOX_ID in $SANDBOX_NAMES; do
        teardown_sandbox $SANDBOX_ID 1>&2
    done

    if type -a handle_uninstall &>/dev/null; then
        handle_uninstall
    fi
}

function install() {
    :
}

function apis() {
    # <version>/<api>
    echo "v1/install v1/uninstall v1/list v1/start v1/stop v1/update v1/mutate v1/version"
}

function version() {
    echo 1.${TEMPLATE_VERSION:-0}.${VERSION:-0}
}

function env_init() {
    if ! which jq &>/dev/null; then
        if [ $(cat /etc/os-release | grep CentOS | wc -l) -gt 0 ]; then
            yum install -y jq &>/dev/null
        else
            apt install -y jq &>/dev/null
        fi
        if ! which jq &>/dev/null; then
            echo "failed to install jq" >&2
            exit 1
        fi
    fi
    if ! which docker &>/dev/null; then
        echo "docker is not installed" >&2
        exit 1
    elif ! docker info &>/dev/null; then
        echo "dockerd is not running" >&2
        exit 1
    fi
}

function help() {
    echo "usage: instance manager of $TASK_NAME - v$VERSION" >&2
    echo "  $0 start <-v /path/to/volume> <-l nic-dev> [-e image=image-uri] [inst-id]" >&2
    echo "  $0 stop <inst-id>" >&2
    echo "  $0 list" >&2
    echo "  $0 update [runtime...]" >&2
    echo "  $0 mutate <nodeInfo>" >&2
    echo "  $0 install" >&2
    echo "  $0 uninstall" >&2
    echo "  $0 apis" >&2
    echo "  $0 version" >&2
}

function main() {
    case $1 in
    "list")
        shift
        list "$@"
        ;;
    "start")
        shift
        start "$@"
        ;;
    "update")
        shift
        update "$@"
        ;;
    "stop")
        shift
        stop "$@"
        ;;
    "mutate")
        shift
        mutate "$@"
        ;;
    "install")
        shift
        install "$@"
        ;;
    "uninstall")
        shift
        uninstall "$@"
        ;;
    "apis")
        shift
        apis "$@"
        ;;
    "version")
        shift
        version "$@"
        ;;
    *) help ;;
    esac
}

env_init
main "${@}"
