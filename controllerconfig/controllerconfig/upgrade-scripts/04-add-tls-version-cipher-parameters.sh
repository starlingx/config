#!/bin/bash
#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script includes in upgraded systems the requirements for
# the min TLS version and cipher suites to be used by k8s API.
#
# This script rely on 'security-kubeapi-service-parameters-apply.py'
# to apply the parameters to kubeapi, needing to be executed before it.
#

# The scripts are passed these parameters:
NAME=$(basename $0)
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

function log {
    echo "$(date -Iseconds | cut -d'+' -f1): ${NAME}[$$]: INFO: $*" >> "/var/log/software.log" 2>&1
}

RETRY_COMMAND=3
TRY_SLEEP=15

# Only run this script during upgrade-activate and from release 22.12
if [[ "$ACTION" != "activate" ||  "$FROM_RELEASE" != "22.12" ]]; then
    log "Skipping tls-cipher-suites,tls-min-version service parameter addition."
    exit 0
fi

source /etc/platform/openrc

log "Adding required parameters to kubernetes API."

for try in $(seq 1 $RETRY_COMMAND); do
    ret=$( (system service-parameter-add kubernetes kube_apiserver tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384 && \
    system service-parameter-add kubernetes kube_apiserver tls-min-version=VersionTLS12) 2>&1 >/dev/null )

    if [[ $? -eq 0 ]]; then
        log "TLS parameters added."
        exit 0
    else
        if [[ $ret == *"Parameter already exists"* ]]; then
            log "TLS parameters already exist."
            exit 0
        fi
        if [[ $try = "$RETRY_COMMAND" ]]; then
            log "Command service-parameter-add failed. Exiting for manual intervention or retry of the activation."
            exit 1
        else
            log "Error adding TLS parameters for kube-apiserver, retrying. Attemp $try of $RETRY_COMMAND."
            sleep $TRY_SLEEP
        fi
    fi
done
