#!/bin/bash
#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# The script restarts the vault server pods following the recommended Hashicorp vault procedure,
# and verifies that the vault application and its server pods have been upgraded to the desired
# version.

# The migration scripts are passed these parameters:
NAME=$(basename $0)
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

# Configs
KUBECOMMAND="kubectl --kubeconfig=/etc/kubernetes/admin.conf"
STATE_APPLIED="applied"
POD_STATUS_RUNNING="Running"
POD_STATUS_SEALED="false"

ACCEPTED_ACTION="activate"
ACCEPTED_FROM="22.12"
ACCEPTED_TO="24.09"

VAULT_APP_NAME="vault"
PIA_APP_NAME="platform-integ-apps"
VAULT_NS="vault"
VAULT_NEW_VERSION="1.14.0"

SLEEP_APP_STATUS=60
SLEEP_MANAGER_RUNNING=10
SLEEP_INJECTOR_RUNNING=10
SLEEP_POD_STATUS=30
SLEEP_POD_VERSION=0

TRIES_APP_STATUS=10
TRIES_MANAGER_RUNNING=6
TRIES_INJECTOR_RUNNING=6
TRIES_POD_STATUS=4
TRIES_POD_VERSION=1

ACTIVE_PODS=""
STANDBY_PODS=""

source /etc/platform/openrc

function log {
    echo "$(date -Iseconds | cut -d'+' -f1): ${NAME}[$$]: INFO: $*" >> "/var/log/software.log" 2>&1
}

# A wrapper function for checking vault status for upgrade. It will check using the provided
# command for a specified amount of time, sleeping between each tries as specified.
# Parameters:
#   sleep_cond: number of seconds to sleep after each tries
#   tries_cond: number of tries to check the condition
#   cmd_cond: command used to check the condition
function check_cond {
    local sleep_cond="$1"
    local tries_cond="$2"
    local cmd_cond="$3"
    local res_cond=""
    local success_cond=false

    for i in $(seq "$tries_cond"); do
        res_cond="$( $cmd_cond )"
        if [ "$res_cond" = "0" ]; then
            success_cond=true
            break
        fi
        if [ "$i" -lt "$tries_cond" ]; then
            sleep "$sleep_cond"
        fi
    done

    if ! $success_cond; then
        return 1
    else
        return 0
    fi
}

# updates global variables ACTIVE_PODS and STANDBY_PODS
function update_active_standby {
    local podname
    local podstatus

    pods="$( $KUBECOMMAND get pods -n $VAULT_NS -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.metadata.labels.vault-active}{"\n"}{end}' | grep "^sva-vault-[0-9] " )"

    while read -r podname podstatus; do
        if [ "$podstatus" = "true" ]; then
            ACTIVE_PODS="$ACTIVE_PODS $podname"
        else
            STANDBY_PODS="$STANDBY_PODS $podname"
        fi
    done <<< "$pods"
}

# Wrapper for pod delete command, with error logging
function delete_pod {
    local pod_name="$1"
    local pod_del_result=""

    pod_del_result="$( $KUBECOMMAND delete pods -n $VAULT_NS "$pod_name" 2>&1 )"
    if [[ "$?" -ne 0 ]] ; then
        log "Error occured during deleting pod $pod_name. Vault upgrade failed. Error: $pod_del_result"
        return 1
    fi

    return 0
}

# Adding a shellcheck disable to bypass the "function is not used" warning.
# The function is passed to the check_cond function above as a string.
# shellcheck disable=SC2317
function check_app_status {
    local pia_status
    local vault_status
    local vault_version

    pia_status="$( system application-show "$PIA_APP_NAME" --format value --column status )"
    vault_status="$( system application-show "$VAULT_APP_NAME" --format value --column status )"
    vault_version="$( system application-show "$VAULT_APP_NAME" --format value --column app_version )"

    if [ "$pia_status" != "$STATE_APPLIED" ]; then
        log "Application $PIA_APP_NAME is currently in status $pia_status. " \
            "It must be in status $STATE_APPLIED."
        echo "1"
    elif [ "$vault_status" != "$STATE_APPLIED" ] || \
        [[ "$vault_version " != "$TO_RELEASE"* ]]; then
        log "Application $VAULT_APP_NAME is currently in status $vault_status " \
            "and version $vault_version. It must be in status $STATE_APPLIED " \
            "and version $TO_RELEASE."
        echo "1"
    else
        echo "0"
    fi
}

# shellcheck disable=SC2317
function check_pod_status {
    local pod_name="$1"
    local pod_running
    local pod_sealed

    pod_running="$( $KUBECOMMAND get pods -n "$VAULT_NS" "$pod_name" -o jsonpath='{.status.phase}' )"
    pod_sealed="$( $KUBECOMMAND get pods -n "$VAULT_NS" "$pod_name" -o jsonpath='{.metadata.labels.vault-sealed}' )"

    if [ "$pod_running" != "$POD_STATUS_RUNNING" ]; then
        log "$pod_name is currently in status $pod_running. It must be in status $POD_STATUS_RUNNING."
        echo "1"
    elif [ "$pod_sealed" != "$POD_STATUS_SEALED" ]; then
        log "The pod is currently in sealed status $pod_sealed. It must be in sealed status $POD_STATUS_SEALED."
        echo "1"
    else
        echo "0"
    fi
}

# shellcheck disable=SC2317
function check_pod_version {
    local pod_name="$1"
    local pod_version

    pod_version="$( $KUBECOMMAND get pods -n "$VAULT_NS" "$pod_name" -o jsonpath='{.metadata.labels.vault-version}' )"

    if [ "$pod_version" = "$VAULT_NEW_VERSION" ]; then
        echo "0"
    else
        log "$pod_name has not been upgraded to version $VAULT_NEW_VERSION, " \
            "from its current version $pod_version."
        echo "1"
    fi
}

# Accepts either "vault-manager" or "vault-agent-injector" as parameters
# shellcheck disable=SC2317
function check_mi_status {
    local pod_name="$1"
    local pod_list
    local pod_count
    local pod_full_name
    local pod_status

    pod_list="$( $KUBECOMMAND get pods -n "$VAULT_NS" -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.phase}{"\n"}{end}' | grep "sva-$pod_name" )"
    pod_count="$(echo "$pod_list" | grep -c "sva-$pod_name" )"
    if [ "$pod_count" -ne 1 ]; then
        log "Incorrect number of $pod_name pods found: $pod_count"
        echo "1"
        return
    fi
    read -r pod_full_name pod_status <<< "$pod_list"
    if [ "$pod_status" != "Running" ]; then
        log "$pod_name pod $pod_full_name is in status $pod_status"
        echo "1"
        return
    fi
    echo 0
}

# only run this script during upgrade-activate
if [ "${ACTION}" != "${ACCEPTED_ACTION}" ]; then
    log "omit upgrade action $ACTION"
    exit 0
fi

# only run if from 22.12 release to 24.09 release
if [ "${FROM_RELEASE}" != "${ACCEPTED_FROM}" ] \
    || [ "${TO_RELEASE}" != "${ACCEPTED_TO}" ]; then
    log "omit action for from release $FROM_RELEASE to release $TO_RELEASE"
    exit 0
fi

# Check if vault application does not exist or is in "uploaded" status.
# If so the vault upgrade is not needed.
VAULT_EXISTS="$( system application-show "$VAULT_APP_NAME" --format value --column status )"
if [ $? -ne 0 ] || [ "$VAULT_EXISTS" = "uploaded" ]; then
    log "Application $VAULT_APP_NAME is not considered for upgrade. Existing script."
    exit 0
fi

# Check application status
check_cond "$SLEEP_APP_STATUS" "$TRIES_APP_STATUS" "check_app_status" || {
    log "Application $VAULT_APP_NAME and/or platform-integ-apps are" \
        "not in healthy status for upgrading vault server pods." \
        "Exiting for manual intervention."
    exit 1
}

# Check the status of vault manager and vault agent injector pods
check_cond "$SLEEP_MANAGER_RUNNING" "$TRIES_MANAGER_RUNNING" "check_mi_status vault-manager" || {
    log "Vault manager pod is currently not in healthy status for upgrading vault server pods." \
        "Exiting for manual intervention."
    exit 1
}

check_cond "$SLEEP_INJECTOR_RUNNING" "$TRIES_INJECTOR_RUNNING" "check_mi_status vault-agent-injector" || {
    log "Vault injector pod is currently not in healthy status."
}

# Find the active and standby pods
update_active_standby

# Delete the standby pods if they are not on the new version
for standby_pod in $STANDBY_PODS; do
    current_version="$( $KUBECOMMAND get pods -n $VAULT_NS "$standby_pod" -o jsonpath='{.metadata.labels.vault-version}' )"
    if [ "$current_version" != "$VAULT_NEW_VERSION" ]; then
        delete_pod "$standby_pod"
    else
        log "Pod $standby_pod already in the new version."
    fi
done

# Check the status of the restarted standby pods
for standby_pod in $STANDBY_PODS; do
    check_cond "$SLEEP_POD_STATUS" "$TRIES_POD_STATUS" "check_pod_status $standby_pod" || {
        log "Pod $standby_pod is not corrently in healthy status."\
        "Exiting for manual intervention."
        exit 1
    }
done

# Check the version of the restarted standby pods
for standby_pod in $STANDBY_PODS; do
    check_cond "$SLEEP_POD_VERSION" "$TRIES_POD_VERSION" "check_pod_version $standby_pod" || {
        log "Pod $standby_pod has not been upgraded correctly."\
        "Exiting for manual intervention."
        exit 1
    }
done

# Delete the active pod if it is not on the new version
for active_pod in $ACTIVE_PODS; do
    current_version="$( $KUBECOMMAND get pods -n $VAULT_NS "$active_pod" -o jsonpath='{.metadata.labels.vault-version}' )"
    if [ "$current_version" != "$VAULT_NEW_VERSION" ]; then
        delete_pod "$active_pod"
    else
        log "Pod $active_pod already in the new version."
    fi
done

# Check the status of the restarted pods
for active_pod in $ACTIVE_PODS; do
    check_cond "$SLEEP_POD_STATUS" "$TRIES_POD_STATUS" "check_pod_status $active_pod" || {
        log "Pod $active_pod is not corrently in healthy status."\
        "Exiting for manual intervention."
        exit 1
    }
done

# Check the version of the restarted pods
for active_pod in $ACTIVE_PODS; do
    check_cond "$SLEEP_POD_VERSION" "$TRIES_POD_VERSION" "check_pod_version $active_pod" || {
        log "Pod $active_pod has not been upgraded correctly."\
        "Exiting for manual intervention."
        exit 1
    }
done

log "Vault upgrade completed."
exit 0
