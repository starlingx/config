#!/bin/bash
#
# Copyright (c) 2022-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#
# This migration script is used for update openldap users during the
# activate stage of a platform upgrade. It will:
# - import data from a previous backup
# - change admin user's primary group from 'root' to 'users'

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
log "$NAME: Starting updating openldap users from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"

if [[ "${ACTION}" == "activate" ]] && [[ "${TO_RELEASE}" == "22.12" ]]; then

    DISTRIBUTED_CLOUD_ROLE=$(source /etc/platform/platform.conf; \
    echo $distributed_cloud_role)

    if [[ $DISTRIBUTED_CLOUD_ROLE == "subcloud" ]] ; then
        log "$NAME: No actions required for this system type"
        exit 0
    fi

    if [[ "${FROM_RELEASE}" == "21.12" ]]; then
        BACKUP_DIR="/opt/platform/config/$FROM_RELEASE/ldap"
        /usr/sbin/slapadd -F /etc/ldap/schema -l $BACKUP_DIR/ldap.db
        log "$NAME: Successfully imported ldap data from $BACKUP_DIR/ldap.db"
    fi

    /usr/sbin/ldapsetprimarygroup admin users

    RC=$?
    if [ ${RC} -eq 0 ]; then
        log "$NAME: Successfully updated openldap users. Script finished successfully."
    else
        log "$NAME: ERROR - failed to update openldap users. (RETURNED: $RC)"
        exit 1
    fi
else
    log "$NAME: No actions required for from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"
fi

exit 0

