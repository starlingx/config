#!/bin/bash
#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# This script is used to resize the platform (and backup, consequently) filesystems
# on System Controller DC, so that to allow an increased parallelism on subclouds
# deployment (100+ deployments in parallel). This script will:
# - Check if deployment is System Controller DC from distributed_cloud_role variable
#   sourced from /etc/platform/platform.conf
# - Check if platform filesystem needs to be resized (i.e. if less than 20GB in size)
#   and skip the execution if not
# - Check if there is enough space on cgts-vg to resize on both controllers
# - Resize backup filesystem on each controller and check if resized successfully
# - Resize platform controllerfs and check if resized successfully
# - NOTE: this script has to be idempotent and reentrant, since upgrade-activate can
#   be called multiple times during the upgrade
# - NOTE: this script must not fail the upgrade if there is not enough disk space to
#   resize, and only have to warn the user about the limitation

NAME=$(basename $0)

# The migration scripts are passed these parameters:
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

EXPANDED_PLATFORM_SIZE=20
NODE_LIST=(controller-0 controller-1)
RESIZE_SLEEP_TIME=60
RESIZE_CHECK_MAX_RETRIES=5

source /etc/platform/openrc
source /etc/platform/platform.conf

# This will log to /var/log/platform.log
function log {
    logger -p local1.info $1
}

function verify_fs_need_resizing {
    _PLATFORM_SIZE=$(
        system controllerfs-list --column name --column size --column state | grep platform | awk '{ print $4; }'
    )

    echo $_PLATFORM_SIZE # return value so that it can be assigned to variable
    if [[ $_PLATFORM_SIZE -ge $EXPANDED_PLATFORM_SIZE ]]; then
        return 1
    fi
    return 0
}

function verify_space_to_resize {
    _PLATFORM_SIZE=$1
    _HOSTNAME=$2

    _AVAILABLE_DISK_SIZE=$(system host-lvg-list $_HOSTNAME | grep cgts-vg | awk '{ print $12; }')
    _INCREASE_DISK_SIZE=$(echo "$EXPANDED_PLATFORM_SIZE - $_PLATFORM_SIZE" | bc)
    _TOTAL_INCREASE_DISK_SIZE=$(echo "2 * $_INCREASE_DISK_SIZE" | bc) # need to resize platform and backup
    log "$NAME: [$_HOSTNAME] Available cgts-vg space: ${_AVAILABLE_DISK_SIZE}G, need ${_TOTAL_INCREASE_DISK_SIZE}G to resize."

    echo $_INCREASE_DISK_SIZE # return value so that it can be assigned to variable
    return $(echo "! $_AVAILABLE_DISK_SIZE >= $_TOTAL_INCREASE_DISK_SIZE" | bc)
}

function resize_backup_filesystem {
    _INCREASE_DISK_SIZE=$1
    _HOSTNAME=$2

    _BACKUP_SIZE=$(system host-fs-list $_HOSTNAME | grep backup | awk '{ print $6; }')
    _EXPANDED_BACKUP_SIZE=$(echo "$_BACKUP_SIZE + $_INCREASE_DISK_SIZE" | bc)
    log "$NAME: [$_HOSTNAME] Current backup size is ${_BACKUP_SIZE}G, new size will be ${_EXPANDED_BACKUP_SIZE}G."
    system host-fs-modify $_HOSTNAME backup=$_EXPANDED_BACKUP_SIZE
    sleep 5

    _BACKUP_SIZE=$(system host-fs-list $_HOSTNAME | grep backup | awk '{ print $6; }')
    return $(echo "! $_BACKUP_SIZE == $_EXPANDED_BACKUP_SIZE" | bc)
}

function resize_platform_controllerfs {
    _PLATFORM_SIZE=$1
    log "$NAME: Current platform size is ${_PLATFORM_SIZE}G, new size will be ${EXPANDED_PLATFORM_SIZE}G."
    system controllerfs-modify platform=$EXPANDED_PLATFORM_SIZE

    for RETRY in $(seq $RESIZE_CHECK_MAX_RETRIES); do
        log "$NAME: Retry $RETRY of $RESIZE_CHECK_MAX_RETRIES, checking if platform filesystem is resized and available..."
        OUTPUT=$(system controllerfs-list --column name --column size --column state | grep platform)
        _CURRENT_PLATFORM_SIZE=$(echo $OUTPUT | awk '{ print $4; }')
        _CURRENT_PLATFORM_STATE=$(echo $OUTPUT | awk '{ print $6; }')
        log "$NAME: Current platform fs size/state: ${_CURRENT_PLATFORM_SIZE}/${_CURRENT_PLATFORM_STATE}"
        if [[ ($_CURRENT_PLATFORM_SIZE -eq $EXPANDED_PLATFORM_SIZE) && ($_CURRENT_PLATFORM_STATE == "available") ]]; then
            return 0
        fi
        sleep $RESIZE_SLEEP_TIME
    done

    if [[ $_CURRENT_PLATFORM_SIZE -eq $EXPANDED_PLATFORM_SIZE ]]; then
        log "$NAME: [WARNING] platform fs is resized but not yet in available state."
        return 0
    fi
    return 1
}

# Script start
log "$NAME: Starting filesystems resize on DC System Controller for increased parallel subcloud deployment for \
    from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"

if [[ "$ACTION" == "activate" ]]; then
    if [[ $distributed_cloud_role == "systemcontroller" ]]; then
        log "$NAME: Verifying if filesystems need resizing..."
        if ! PLATFORM_SIZE=$(verify_fs_need_resizing); then
            log "$NAME: No need to resize, platform filesystem has been resized already."
            exit 0
        fi
        log "$NAME: Platform filesystem needs resizing, current size is ${PLATFORM_SIZE}G,\
            ideal size is ${EXPANDED_PLATFORM_SIZE}G."

        log "$NAME: Verifying if there is enough available space to resize..."
        for NODE in "${NODE_LIST[@]}"; do
            if ! INCREASE_DISK_SIZE=$(verify_space_to_resize $PLATFORM_SIZE $NODE); then
                log "$NAME: Not enough space in cgts-vg on $NODE to resize, parallel subcloud deployment will be \
                    limited. Resize operations will be skipped."
                exit 0
            fi
        done
        log "$NAME: LVG cgts-vg has enough space for resizing, continuing with resize operations..."

        log "$NAME: Trying to resize host-fs backup for both controllers..."
        for NODE in "${NODE_LIST[@]}"; do
            if ! resize_backup_filesystem $INCREASE_DISK_SIZE $NODE; then
                log "$NAME: Failed while resizing backup fs on $NODE, resize operation aborted."
                exit 0
            fi
            log "$NAME: Successfully resized backup filesystem on $NODE."
        done

        log "$NAME: Trying to resize controllerfs platform filesystem..."
        if ! resize_platform_controllerfs $PLATFORM_SIZE; then
            log "$NAME: Failed while resizing controllerfs platform filesystem, resize operation aborted."
            exit 0
        fi
        log "$NAME: Successfully resized controllerfs platform filesystem."
    else
        log "$NAME: Not a DC System Controller deployment. No filesystem resize needed."
    fi
    log "$NAME: Filesystems resizing for DC System Controller finished successfully for \
        from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"
else
    log "$NAME: No actions required for from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"
fi

exit 0
