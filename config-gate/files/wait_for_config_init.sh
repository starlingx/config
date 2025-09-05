#!/bin/bash
#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# Wait for base node config service
. /etc/platform/platform.conf

SERVICE=

script_name=$(basename "$0")

case $nodetype in
    controller)
        SERVICE=controllerconfig.service
        ;;
    worker)
        SERVICE=workerconfig.service
        ;;
    storage)
        SERVICE=storageconfig.service
        ;;
    *)
        exit 1
        ;;
esac

while :; do
    status="$(systemctl status ${SERVICE} 2>&1)"
    # verify systemctl status response format
    # <service> - <Description>
    # ...
    if echo "${status}" | grep -q "${SERVICE}"
    then
            if ! echo "${status}" | grep -q running
            then
                msg="${SERVICE} has finished running."
                logger -t "${script_name}" "${msg}"
                echo "${script_name} - ${msg}"
                exit 0
            fi
    else
        logger -t "${script_name}" "${status}"
        echo "${script_name} - ${status}"
    fi
    sleep 1
done
