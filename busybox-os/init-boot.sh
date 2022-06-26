#!/bin/bash
set -e
DEV=/dev/sdb

if [ ! -b "$DEV" ]; then
    echo "not a block device: $DEV"
    exit 1
fi

./gen-initrd.sh

if ! mount | grep -P "$DEV.*/mnt/boot"; then
    mkdir -p /mnt/boot
    mount $DEV /mnt/boot
fi

grub2-install --boot-directory=/mnt/boot --target=i386-pc $DEV
cp -v grub.cfg /mnt/boot/grub2/
cp -v vmlinuz /mnt/boot/
cp -v initrd.gz /mnt/boot/


