#!/bin/bash
#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

NAME=$(basename $0)

function log {
    logger -p local1.info $1
}

log "$NAME: restarting sysinv services"

sm-restart service sysinv-conductor
sleep 2
pmon-restart sysinv-agent

exit 0
