#!/bin/sh
rm -rf ./extracted
mkdir extracted
cd extracted
cpio -i -d -H newc -F ../rootfs.cpio --no-absolute-filenames
cd ../
