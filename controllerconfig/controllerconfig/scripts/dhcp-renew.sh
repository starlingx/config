#!/bin/bash
#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

NAME=$(basename $0)

# The interface name for which the DHCP lease has to be renewed
IFACE=$1

MAX_REMOVE_ATTEMPTS=3
REQUEST_ATTEMPT_TIMES=(0 5 10 15 20)

# This will log to /var/log/platform.log
function log {
    logger -p local1.info $1
}

function remove_lease {
    for attempt in $(/usr/bin/seq 1 $MAX_REMOVE_ATTEMPTS)
    do
        log "$NAME: Removing DHCP lease for interface $IFACE, attempt $attempt"
        /usr/sbin/dhclient -r $IFACE
        if [ $? -eq 0 ]; then
            log "$NAME: Successfully removed DHCP lease for interface $IFACE"
            return
        fi
    done
    log "$NAME: Failed to remove DHCP lease for interface $IFACE"
    exit 1
}

function request_lease {
    for time in "${REQUEST_ATTEMPT_TIMES[@]}"
    do
        if [ "$time" != "0" ]; then
            log "$NAME: Waiting $time seconds before retrying to get a lease for interface $IFACE"
            sleep $time
        fi
        log "$NAME: Requesting DHCP lease for interface $IFACE"
        /usr/sbin/dhclient -1 $IFACE
        if [ $? -eq 0 ]; then
            log "$NAME: Received DHCP lease for interface $IFACE"
            return
        fi
    done
    log "$NAME: Failed to get DHCP lease for interface $IFACE"
    exit 1
}

remove_lease $IFACE
request_lease $IFACE

exit 0
