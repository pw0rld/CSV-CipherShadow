#!/bin/bash

set -e

IMAGE_URL="https://anolis.oss-cn-hangzhou.aliyuncs.com/anolisos_8_6_x64_20G_anck_uefi_community_alibase_20220817.vhd"
IMAGE_NAME="anolisos_8_6_x64_20G_anck_uefi_community_alibase_20220817.vhd"
VM_IMAGE="vm.qcow2"
NBD_DEV="/dev/nbd0"
MOUNT_POINT="/tmp"
ROOT_PASSWORD="root"

cleanup() {
    echo "Cleaning up..."
    if mountpoint -q "$MOUNT_POINT"; then
        umount "$MOUNT_POINT"
    fi
    if [ -e "$NBD_DEV" ]; then
        qemu-nbd -d "$NBD_DEV"
    fi
}

trap cleanup EXIT

echo "Downloading Anolis image..."
if [ ! -f "$IMAGE_NAME" ]; then
    wget "$IMAGE_URL"
else
    echo "Image already exists, skipping download."
fi

echo "Converting image format..."
qemu-img convert -p -f vpc "$IMAGE_NAME" -O qcow2 "$VM_IMAGE"

echo "Setting up NBD..."
modprobe nbd max_part=8
sleep 1

echo "Connecting image to NBD..."
qemu-nbd -c "$NBD_DEV" "$VM_IMAGE"
sleep 1

echo "Modifying root password..."
mount "$NBD_DEV"p2 "$MOUNT_POINT"
chroot "$MOUNT_POINT" sh -c "echo 'root:$ROOT_PASSWORD' | chpasswd"

echo "Done! Image has been prepared successfully."