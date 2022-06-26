#!/bin/bash
set -e

DEV=/dev/sdb2

if [ ! -b "$DEV" ]; then
    echo "not a block device: $DEV"
    exit 1
fi

if ! mount | grep -P "$DEV.*/mnt/sysroot"; then
    mkdir -p /mnt/sysroot
    mount $DEV /mnt/sysroot
fi


cp -a sysroot/* /mnt/sysroot/
