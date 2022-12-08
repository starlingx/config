#!/bin/bash
#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Sometimes docker will be in a bad state.
# Check for this and use some recovery logic to get it back to normal.

# Parameters for recovery logic
MAX_ATTEMPTS=5
TIME_STEP=6

# The migration scripts are passed these parameters:
NAME=$(basename $0)
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

# This will log to /var/log/platform.log
function log {
    logger -p local1.info $1
}

# Script start
if [[ "${ACTION}" != "activate" ]]; then
    exit 0
fi

log "$NAME: Starting docker health check script from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"

# Docker is considered in a "bad state" if the service isn't active or
# if "/var/lib/docker/tmp" doesn't exist, as it won't be able to download images
attempts=0
while [ "$(systemctl is-active docker)" != "active" ] || [ ! -d "/var/lib/docker/tmp" ]
do
    attempts=$(( $attempts + 1 ))
    if [ "$attempts" -gt "$MAX_ATTEMPTS" ]; then
        log "$NAME: Could not fix docker service."
        exit 0
    fi
    log "$NAME: Docker in bad state. Restarting docker service. Attempt: $attempts/$MAX_ATTEMPTS"

    systemctl restart docker

    sleep $TIME_STEP
done

log "$NAME: Docker service is active and healthy"

exit 0
