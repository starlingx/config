#!/bin/bash
#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# This script is used to perform barbican data-migration

NAME=$(basename $0)

# The migration scripts are passed these parameters:
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3
# Checks linux distro because barbican is not upgraded in centos
IS_DEBIAN=$(grep -c "ID=debian" /etc/os-release)

# This will log to /var/log/platform.log
function log {
    logger -p local1.info $1
}

# Script start
log "$NAME: Starting barbican data migration from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"

if [[ "${ACTION}" == "migrate" ]] && [[ "${TO_RELEASE}" == "22.12" ]] && [[ ${IS_DEBIAN} != 0 ]]; then

    /usr/bin/barbican-db-manage upgrade

    log "$NAME: Barbican data migration finished successfully from $FROM_RELEASE to $TO_RELEASE"
else
    log "$NAME: No actions required for from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"
fi

exit 0
