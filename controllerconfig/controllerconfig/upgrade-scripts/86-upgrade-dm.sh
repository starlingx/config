#!/bin/bash
#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This migration script is used to refresh deploy plug-in
# during the activate stage of a platform upgrade.

# The migration scripts are passed these parameters:
NAME=$(basename $0)
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

SOFTWARE_LOG_PATH='/var/log/software.log'

function log {
    echo "$(date -Iseconds | cut -d'+' -f1): ${NAME}[$$]: INFO: $*" >> "/var/log/software.log" 2>&1
}

# Check kubernetes health status.
# Exit with status 1 if sysinv-k8s-health command fails
function check_k8s_health {
    local k8s_health
    sysinv-k8s-health --log-file "${SOFTWARE_LOG_PATH}" check
    k8s_health=$?

    if [ $k8s_health -eq 1 ]; then
        exit 1
    fi
}

DEPLOY_PLAYBOOK=$(ls /usr/local/share/applications/playbooks/*deployment-manager.yaml 2> /dev/null)
DEPLOY_CHART=$(ls /usr/local/share/applications/helm/*-deployment-manager*.tgz 2> /dev/null)
DEPLOY_OVERRIDES=$(ls /usr/local/share/applications/overrides/*deployment-manager-overrides.yaml 2> /dev/null)
REFRESH_DM_IMAGES="false"

if [[ "${ACTION}" == "activate" ]]; then
    check_k8s_health
    if kubectl --kubeconfig=/etc/kubernetes/admin.conf get namespace| grep -q deployment-manager
    then
        if [[ -z "${DEPLOY_OVERRIDES}" ]] || [[ -z "${DEPLOY_PLAYBOOK}" ]] || [[ -z "${DEPLOY_CHART}" ]]; then
            log "Script execution is skipped. There are no deploy files."
        else
            log "Refreshing deploy plug-in from $FROM_RELEASE to $TO_RELEASE"
            /usr/local/bin/update-dm.sh ${DEPLOY_PLAYBOOK} \
                                        ${DEPLOY_CHART} \
                                        ${DEPLOY_OVERRIDES} \
                                        ${REFRESH_DM_IMAGES}
            exit $?
        fi
    else
        log "Script execution is skipped. There is no deploy plug-in running in ${FROM_RELEASE}."
    fi
else
    log "No actions required for from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"
fi

exit 0
