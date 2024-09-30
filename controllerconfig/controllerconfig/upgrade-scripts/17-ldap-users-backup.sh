#!/bin/bash
#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#
# This start script is used to back up ldap data from 21.12
# so that it can be used later for importing after a platform upgrade.

# The scripts are passed these parameters:
NAME=$(basename $0)
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

function log {
    echo "$(date -Iseconds | cut -d'+' -f1): ${NAME}[$$]: INFO: $*" >> "/var/log/software.log" 2>&1
}

# Logs using the 'log' function and exits with error
function exit_with_error {
    log "$1 (RETURNED: $?)"
    exit 1
}

# Script start
log "Saving backup of openldap schema files from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"

if [[ "${ACTION}" == "start" ]] && [[ "${FROM_RELEASE}" == "21.12" ]] && [[ "${TO_RELEASE}" == "22.12" ]]; then

    DISTRIBUTED_CLOUD_ROLE=$(source /etc/platform/platform.conf; \
    echo $distributed_cloud_role)

    if [[ $DISTRIBUTED_CLOUD_ROLE == "subcloud" ]] ; then
        log "No actions required for subclouds"
        exit 0
    fi

    BACKUP_DIR="/opt/platform/config/$FROM_RELEASE/ldap"

    rm -rf $BACKUP_DIR \
    || exit_with_error "ERROR - Failed to remove directory $BACKUP_DIR"

    mkdir $BACKUP_DIR \
    || exit_with_error "ERROR - Failed to create directory $BACKUP_DIR"

    log "Successfully created directory $BACKUP_DIR"

    /usr/sbin/slapcat -F /etc/openldap/schema -l $BACKUP_DIR/ldap.db \
    || exit_with_error "ERROR - Failed to export ldap data to $BACKUP_DIR/ldap.db"

    log "Successfully exported $BACKUP_DIR/ldap.db"

    chmod -R go= $BACKUP_DIR \
    || exit_with_error "ERROR - Failed to set permissions to $BACKUP_DIR/ldap.db"

    log "Successfully set permissions for $BACKUP_DIR/ldap.db"

    log "Script finished successfully."
else
    log "No actions required for from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"
fi

exit 0

