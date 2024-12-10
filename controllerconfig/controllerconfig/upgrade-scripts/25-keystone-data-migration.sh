#!/bin/bash
#
# Copyright (c) 2022-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# This script is used to perform keystone data-migration

NAME=$(basename $0)

# The migration scripts are passed these parameters:
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3
# Checks linux distro because keystone is not upgraded in centos
IS_DEBIAN=$(grep -c "ID=debian" /etc/os-release)

function log {
    echo "$(date -Iseconds | cut -d'+' -f1): ${NAME}[$$]: INFO: $*" >> "/var/log/software.log" 2>&1
}

# Script start
log "Starting keystone data migration from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"

if [[ "${ACTION}" == "migrate" ]] && [[ "${TO_RELEASE}" == "22.12" ]] && [[ ${IS_DEBIAN} != 0 ]]; then

    touch /var/log/keystone/keystone.log
    chown keystone:keystone /var/log/keystone/keystone.log
    /usr/bin/keystone-manage db_sync

    log "Keystone data migration finished successfully from $FROM_RELEASE to $TO_RELEASE"
else
    log "No actions required for from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"
fi

exit 0
