#!/bin/bash
#
# Copyright (c) 2022-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# This script is used to recreate vim/nfv endpoints in
# SystemController public interface when upgrading
# - Part of a bugfix related to keystone_endpoint module
# - If new upgrade paths are added from versions before
#   22.12, this script must be updated to account for it.
#   I.e. add another clause in: 
#   if .. && [[ "${FROM_RELEASE}" == "XX.XX" ]]

NAME=$(basename $0)

# The migration scripts are passed these parameters:
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3
# Checks linux distro because keystone is not upgraded in centos
IS_DEBIAN=$(grep -c "ID=debian" /etc/os-release)

#Get some variables
source /etc/platform/platform.conf

#Define some strings
HIERADATA_FOLDER="/opt/platform/puppet/${sw_version}/hieradata"
TMP_FOLDER=$(mktemp -d /tmp/XXXXX)
MANIFEST_NAME="remove_vim"
MANIFEST_FILE="${TMP_FOLDER}/${MANIFEST_NAME}.yaml"

function log {
    echo "$(date -Iseconds | cut -d'+' -f1): ${NAME}[$$]: INFO: $*" >> "/var/log/software.log" 2>&1
}

# Script start
log "Starting to recreate vim's keystone endpoints in SystemController from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"

if [[ "${ACTION}" == "activate" ]] && [[ "${FROM_RELEASE}" == "22.12" ]] && [[ ${IS_DEBIAN} != 0 ]] && [[ $distributed_cloud_role == "systemcontroller" ]]; then

    source /etc/platform/openrc

    #Remove all endpoints for vim in SystemController region
    log "Removing old vim keystone endpoints for SystemController"
    openstack endpoint list --region SystemController --service nfv -f value -c ID | \
    xargs -r openstack endpoint delete

    #Write manifest that recreates the endpoints
    echo 'classes:' > ${MANIFEST_FILE}
    echo '- platform::params' >> ${MANIFEST_FILE}
    echo '- dcorch::keystone::auth' >> ${MANIFEST_FILE}

    #Find active controller's mgmt IP
    ACTIVE_CONTROLLER_IP=$(cat /etc/hosts | awk -v host=$HOSTNAME '$2 == host {print $1}')

    log "Using $HOSTNAME mgmt IP to apply manifest on puppet - $ACTIVE_CONTROLLER_IP"

    #Run manifest
    /usr/local/bin/puppet-manifest-apply.sh ${HIERADATA_FOLDER} ${ACTIVE_CONTROLLER_IP} controller runtime ${MANIFEST_FILE}

    #Remove the file
    rm ${MANIFEST_FILE}

    log "SystemController's vim endpoints recreation finished successfully from $FROM_RELEASE to $TO_RELEASE"
else
    log "No actions required for from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"
fi

exit 0
