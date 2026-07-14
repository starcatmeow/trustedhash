#!/bin/bash
parted -s /dev/vdb mklabel gpt mkpart primary 0% 100%
mkfs.vfat -F 32 /dev/vdb1
mkdir mnt
mount /dev/vdb1 mnt
cd mnt
mkdir -p EFI/BOOT
curl -fL --output EFI/BOOT/BOOTX64.EFI https://github.com/pbatard/UEFI-Shell/releases/download/26H1/shellx64.efi
curl -fLO https://github.com/NoInitRD/Memory-Dump-UEFI/raw/refs/heads/main/Build/MemoryDump.efi
