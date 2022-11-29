#!/bin/bash
#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script resets permissions of some Kubernetes *.key files to 0600 on controller-0 only.

FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

# This will log to /var/log/platform.log
function log {
    logger -p local1.info $1
}

reset-k8s-key-file-permissions()
{
    APISERVER_KEY="/etc/kubernetes/pki/apiserver-etcd-client.key"
    CA_KEY="/etc/kubernetes/pki/ca.key"
    declare -a FILE_LIST=("$APISERVER_KEY" "$CA_KEY" )

    for file in "${FILE_LIST[@]}"; do
        if [ -f "$file" ]; then
            log "Resetting permissions for file $file ..."
            chmod 0600 $file
        fi
    done

    log "Kubernetes key files permissions successfully reset."
}

log "Script $0 invoked with from_release = $FROM_RELEASE to_release = $TO_RELEASE action = $ACTION"

if [ "$TO_RELEASE" == "22.12" ] && [ "$ACTION" == "activate" ]; then
    reset-k8s-key-file-permissions
else
    log "Script $0 execution skipped"
fi

exit 0
