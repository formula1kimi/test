#!/bin/sh
set -e
cd initrd
find . | cpio -o -H newc --quiet | gzip -9 > ../initrd.gz
