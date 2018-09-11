#!/bin/bash
#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# Wait for base node config service
. /etc/platform/platform.conf

SERVICE=

case $nodetype in
    controller)
        SERVICE=controllerconfig.service
        ;;
    compute)
        SERVICE=computeconfig.service
        ;;
    storage)
        SERVICE=storageconfig.service
        ;;
    *)
        exit 1
        ;;
esac

while :; do
    systemctl status $SERVICE |grep -q running
    if [ $? -ne 0 ]; then
        exit 0
    fi
    sleep 1
done

