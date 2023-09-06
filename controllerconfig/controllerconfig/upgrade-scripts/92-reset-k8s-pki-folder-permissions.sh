#!/bin/bash
#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script resets the permissions of folder "/etc/kubernetes/pki" to 755 on controller-0 only.

FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

# This will log to /var/log/platform.log
function log {
    logger -p local1.info $1
}

reset-k8s-pki-folder-permissions()
{
    FOLDER_PATH="/etc/kubernetes/pki"
    if [ -d "$FOLDER_PATH" ]; then
        log "Resetting permissions for folder $FOLDER_PATH ..."
        chmod 755 $FOLDER_PATH
    fi

    log "Kubernetes pki folder permissions successfully reset."
}

log "Script $0 invoked with from_release = $FROM_RELEASE to_release = $TO_RELEASE action = $ACTION"

if [ "$TO_RELEASE" == "24.03" ] && [ "$ACTION" == "activate" ]; then
    reset-k8s-pki-folder-permissions
else
    log "Script $0 execution skipped"
fi

exit 0
