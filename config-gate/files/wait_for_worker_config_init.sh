#!/bin/bash
#
# Copyright (c) 2016-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# Wait for worker config service

SERVICE=workerconfig.service

while :; do
    read -r RESULT ACTIVE_STATE SUB_STATE < <(
        systemctl show "$SERVICE" -p ActiveState -p SubState -p Result --value |
            paste - - -
    )
    if [[ "$ACTIVE_STATE" == "inactive" && "$RESULT" == "success" && "$SUB_STATE" == "dead" ]]; then
        exit 0
    elif [[ "$ACTIVE_STATE" == "active" && "$RESULT" == "success" && "$SUB_STATE" == "exited" ]]; then
        exit 0
    elif [[ "$ACTIVE_STATE" == "failed" || "$RESULT" == "failed" ]]; then
        exit 1
    fi
    sleep 1
done

