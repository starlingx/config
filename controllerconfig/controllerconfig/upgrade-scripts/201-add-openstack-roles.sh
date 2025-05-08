#!/bin/bash
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This migration script is used to create keystone roles
# operator and configurator during upgrade, also deletes
# roles when the rollback is executed
#

# The migration scripts are passed these parameters:
NAME=$(basename $0)
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3
ROLES=("operator" "configurator")

function log {
    echo "$(date -Iseconds | cut -d'+' -f1): ${NAME}[$$]: INFO: $*" >> "/var/log/software.log" 2>&1
}

# Only run this script during upgrade-activate and from release 24.09
if [[ "$ACTION" == "activate" && "$FROM_RELEASE" == "24.09" ]]; then
    log "creating keystone roles operator,configurator"
    for role in "${ROLES[@]}"; do
        openstack role show $role
        RC=$?
        if [ ${RC} == 1 ]; then
            openstack role create $role
            RC=$?
            if [ ${RC} == 0 ]; then
                log "Successfully added keystone role ${role}"
            else
                log "Failed to add keystone role ${role}"
                exit 1
            fi
        fi
    done
elif [[ "$ACTION" == "activate-rollback" && "$TO_RELEASE" == "24.09" ]]; then
    for role in "${ROLES[@]}"; do
        openstack role show $role
        RC=$?
        if [ ${RC} == 0 ]; then
            openstack role delete $role
            RC=$?
            if [ ${RC} == 0 ]; then
                log "Successfully deleted keystone role ${role}"
            else
                log "Failed to delete keystone role ${role}"
                exit 1
            fi
        fi
    done
fi
