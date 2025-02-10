#!/bin/bash
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script adds system service parameters for service kubernetes
# for sections kube_scheduler and kube_controller_manager.
#
# This script relies on 'kubernetes-service-parameters-apply.py'
# to apply the parameters to kubeapi, needing to be executed before it.
#
# As this script does not restart any kubernetes components, we do not
# need to run k8s health check here.
#

NAME=$(basename "$0")

# The migration scripts are passed these parameters:
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

SOFTWARE_LOG_PATH="/var/log/software.log"

function log {
    echo "$(date -Iseconds | cut -d'+' -f1): ${NAME}[$$]: INFO: $*" >> "${SOFTWARE_LOG_PATH}" 2>&1
}

log "Disable leader election for kube-scheduler and kube-controller-manager"\
    "from $FROM_RELEASE to $TO_RELEASE with action $ACTION"

if [[ "${ACTION}" == "activate" ]]; then
    source /etc/platform/platform.conf
    if [[ "${nodetype}" == "controller" ]] && [[ "${system_mode}" == "simplex" ]]; then
        source /etc/platform/openrc
        for section in kube_scheduler kube_controller_manager; do
            value=$(system service-parameter-list --service kubernetes \
                    --section "${section}" --format value | awk '/leader-elect/ {print $5}')
            if [[ "${value}" == "false" ]]; then
                log "Service parameter leader-elect=false already exists for section ${section}."\
                    "Nothing to do."
            elif [[ "${value}" == "" ]]; then
                system service-parameter-add kubernetes "${section}" leader-elect=false
                RC=$?
                if [ ${RC} == 0 ]; then
                    log "Successfully added service parameter leader-elect=false for ${section}"
                else
                    log "Command service-parameter-add failed for section ${section}."\
                        "Exiting for manual intervention or retry of the activation."
                    exit 1
                fi
            else
                # 'true' or any garbage value
                system service-parameter-modify kubernetes "${section}" leader-elect=false
                RC=$?
                if [ ${RC} == 0 ]; then
                    log "Successfully updated service parameter leader-elect=false for ${section}"
                else
                    log "Command service-parameter-modify failed for section ${section}."\
                        "Exiting for manual intervention or retry of the activation."
                    exit 1
                fi
            fi
        done
    else
        log "No actions required for ${system_mode}-${nodetype}"
    fi
else
    log "No actions required from release ${FROM_RELEASE} to ${TO_RELEASE} with action ${ACTION}"
fi

exit 0
