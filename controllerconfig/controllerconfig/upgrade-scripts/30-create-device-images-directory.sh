#!/bin/bash
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will create the directory /opt/platform/device_images
# if it does not exist.
#
# This script is needed for upgrade from release 20.06.
#

NAME=$(basename $0)

# The migration scripts are passed these parameters:
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

source /etc/platform/openrc

# This will log to /var/log/platform.log
function log {
    logger -p local1.info $1
}

DIR_NAME='/opt/platform/device_images'
if [ "$FROM_RELEASE" == "20.06" ] && [ "$ACTION" == "migrate" ]; then
    if [ ! -d $DIR_NAME ]; then
        log "$NAME: Create directory $DIR_NAME."
        mkdir $DIR_NAME
        if [ $? -ne 0 ]; then
            log "$NAME: Failed to create directory $DIR_NAME"
            exit 1
        fi
    fi
fi

exit 0

