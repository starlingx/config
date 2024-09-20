#!/bin/bash
#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script includes in upgraded systems the requirements for
# the min TLS version and cipher suites to be used by k8s API

# The scripts are passed these parameters:
NAME=$(basename $0)
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

function log {
    echo "$(date -Iseconds | cut -d'+' -f1): ${NAME}[$$]: INFO: $*" >> "/var/log/software.log" 2>&1
}

RETRY_COMMAND=3
RETRY_ALARM=40
TRY_SLEEP=15

# Only run this script during upgrade-activate and from release 22.12
if [[ "$ACTION" != "activate" ||  "$FROM_RELEASE" != "22.12" ]]; then
    log "Skipping tls-cipher-suites,tls-min-version service parameter addition."
    exit 0
fi

source /etc/platform/openrc

log "Applying required parameters to kubernetes API."

applied=false
for try in $(seq 1 $RETRY_COMMAND); do
    system service-parameter-add kubernetes kube_apiserver tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384
    system service-parameter-add kubernetes kube_apiserver tls-min-version=VersionTLS12
    system service-parameter-apply kubernetes

    if [[ $? -eq 0 ]]; then
        log "Apply requested. Will wait for the API to be reconfigurated."
        applied=true
        break
    else
        log "Error while adding commands, retrying. Attemp $try of $RETRY_COMMAND."
        sleep $TRY_SLEEP
    fi
done

if [[ $try = "$RETRY_COMMAND" ]] && [[ $applied = "false" ]]; then
    log "Command service-parameter-apply failed. Exiting for manual intervention or retry of the activation."
    exit 1
fi

# Wait for the config out-of-date
cleared=false
for try in $(seq 1 $RETRY_ALARM); do
    CONFIG_ALARMS=$(fm alarm-list --query alarm_id=250.001)
    if [[ -z "${CONFIG_ALARMS}" ]]; then
        if [[ $cleared = "true" ]]; then
            break
        fi
        cleared=true
    else
        cleared=false
    fi
    log "Wait for configuration out-of-date alarms to clear. Attemp $try of $RETRY_ALARM."
    sleep $TRY_SLEEP
done

if [[ $try = "$RETRY_ALARM" ]] && [[ $cleared = "false" ]]; then
    log "Kubernetes API wasn't reconfigured in the allocated time. Exiting for manual intervention or retry of the activation."
    exit 1
else
    log "Required parameters applied to kubernetes API."
fi

exit 0
