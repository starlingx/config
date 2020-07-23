#!/bin/bash
#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

NAME=$(basename $0)
rootfs_part=$(findmnt -n -o SOURCE /)
device_path=$(lsblk -pno pkname $rootfs_part)

BACKUP_PART_GUID="BA5EBA11-0000-1111-2222-000000000002"
PLATFORM_BACKUP_SIZE=10000
part_type_guid_str="Partition GUID code"
part_first_sector_str="First sector"
part_last_sector_str="Last sector"

# This will log to /var/log/platform.log
function log {
    echo $1
    logger -p local1.info -t $NAME $1
}

log "Checking for valid platform-backup partition on device $device_path"

part_numbers=($(parted -s $device_path print | awk '$1 == "Number" {i=1; next}; i {print $1}'))
sector_size=$(blockdev --getss $device_path)

for part_number in "${part_numbers[@]}"; do
    if [[ $device_path == *"nvme"* ]]; then
        part=${device_path}p${part_number}
    else
        part=$device_path$part_number
    fi
    sgdisk_part_info=$(sgdisk -i $part_number $device_path)
    part_type_guid=$(echo "$sgdisk_part_info" | grep "$part_type_guid_str" | awk '{print $4;}')
    part_fstype=$(blkid -s TYPE -o value $part)
    log "Checking $part fs_type: $part_fstype  sgdisk_info: $sgdisk_part_info"
    if [ "$part_type_guid" == $BACKUP_PART_GUID -a "${part_fstype}" == "ext4" ]; then
        part_start_mib=$(($(echo "$sgdisk_part_info" | grep "$part_first_sector_str" | awk '{print $3;}') * $sector_size / (1024*1024)))
        part_end_mib=$((($(echo "$sgdisk_part_info" | grep "$part_last_sector_str" | awk '{print $3;}') * $sector_size / (1024*1024)) + 1))
        part_size_mib=$((part_end_mib-part_start_mib))
        log "Found platform-backup partition with size: $part_size_mib"
        if [ $part_size_mib -eq $PLATFORM_BACKUP_SIZE ]; then
            log "Success"
            exit 0
        fi
        break
    fi
done
log "Valid platform-backup partition not found"
exit 1