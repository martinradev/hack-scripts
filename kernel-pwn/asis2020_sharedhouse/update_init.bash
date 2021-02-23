#!/bin/bash

echo ./init | cpio -H newc -o >> rootfs.cpio
