#!/bin/bash
#
# Copyright (c) 2022-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#
# This migration script is used for update openldap users during the
# activate stage of a platform upgrade. It will:
# - import data from a previous backup
# - change admin user's primary group from 'root' to 'users'
# - cleanup the centos openldap folder after the users have been imported
# and loaded successfully in an upgrade from a centos release to a debian
# release

# The migration scripts are passed these parameters:
NAME=$(basename $0)
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

function log {
    echo "$(date -Iseconds | cut -d'+' -f1): ${NAME}[$$]: INFO: $*" >> "/var/log/software.log" 2>&1
}

# Script start
log "Starting updating openldap users from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"

if [[ "${ACTION}" == "activate" ]] && [[ "${TO_RELEASE}" == "22.12" ]]; then

    DISTRIBUTED_CLOUD_ROLE=$(source /etc/platform/platform.conf; \
    echo $distributed_cloud_role)

    if [[ $DISTRIBUTED_CLOUD_ROLE == "subcloud" ]] ; then
        log "No actions required for this system type"
        exit 0
    fi

    if [[ "${FROM_RELEASE}" == "21.12" ]]; then
        BACKUP_DIR="/opt/platform/config/$FROM_RELEASE/ldap"
        /usr/sbin/slapadd -F /etc/ldap/schema -l $BACKUP_DIR/ldap.db
        log "Successfully imported ldap data from $BACKUP_DIR/ldap.db"

        log "Remove centos openldap folder"
        rm -rf /etc/openldap

        RC_RM=$?
        if [ ${RC_RM} -eq 0 ]; then
            log "Successfully removed centos openldap folder"
        else
            log "ERROR - failed to remove centos openldap folder. (RETURNED: $RC_RM)"
        fi
    fi

    /usr/sbin/ldapsetprimarygroup admin users

    RC=$?
    if [ ${RC} -eq 0 ]; then
        log "Successfully updated openldap users. Script finished successfully."
    else
        log "ERROR - failed to update openldap users. (RETURNED: $RC)"
        exit 1
    fi
else
    log "No actions required for from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"
fi

exit 0

