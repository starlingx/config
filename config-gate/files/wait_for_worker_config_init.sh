#!/bin/bash
#
# Copyright (c) 2016-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# Wait for worker config service

SERVICE=workerconfig.service

while :; do
    systemctl status $SERVICE |grep -q running
    if [ $? -ne 0 ]; then
        exit 0
    fi
    sleep 1
done

