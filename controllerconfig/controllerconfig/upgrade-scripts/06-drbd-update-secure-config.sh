#!/bin/bash
#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# This migration script is used to toggle on and off during
# upgrade. Using system drdbsync-modify CLI to toggle drbd secure
# configuration.
# - During migrate
#   - Deactivate drbd secure config to keep compatibility to
#     synchonize with other drbd node, which is not upgraded yet
# - During activate
#   - Activate drbd secure config on both controllers since
#     both controllers (DX,STD,STORAGE) are already upgraded in
#     activate phase.
# - During rollback
#   - Since rollback restores the database and puppet hieradata
#     from previous release, it is not necessary to develop an
#     activate-rollback script for these actions.
#
# Note: The 'drbdsync-modify' command modifies an entry in the
#       system configuration database, located in a specific directory
#       related to the current platform version. Potential paths could
#       include '/var/lib/postgresql/<current version>/'.
NAME=$(basename $0)

# The migration scripts are passed these parameters:
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

# This will log to /var/log/platform.log
function log {
    logger -p local1.info $1
}

log "$NAME: Starting drbdconfig secure toggle from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"

if [[ "${ACTION}" == "activate" ]] && [[ "${TO_RELEASE}" == "24.09" ]]; then
    source /etc/platform/openrc
    if system drbdsync-modify --secure True; then
        log "$NAME: drbdconfig secure toggle is True."
    else
        log "$NAME: drbdconfig secure toggle was not possible."
        exit 1
    fi
fi
