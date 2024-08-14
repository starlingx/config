#!/bin/bash
#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# This script is used remove the vault application on activate-rollback.
#
# If this procedure fails, then fail softly - the platform is probably
# failing anyway or hopefully the app status won't cause rollback to
# fail, because:
#
# The procedure for restoring vault on rollback will require removal of
# the application, deleting the namespace, then restoring from a vault
# snapshot.

NAME="$(basename $0)"

# The migration scripts are passed these parameters:
FROM_RELEASE="$1"
TO_RELEASE="$2"
ACTION="$3"

APP_NAME="vault"
APP_NS="vault"
PODS_PREFIX="sva-vault"
ORIG_SERVER_VERSION="1.9.2"

SUPPORTED_FROM_RELEASE="24.09"
SUPPORTED_TO_RELEASE="22.12"

# wait 180s minutes for application transition to complete
APP_WAIT_TRIES=12
APP_WAIT_INTERVAL=15

# try arbitrarily 3 times to remove the application
# wait 60s before retrying
REMOVE_TRIES=3
REMOVE_INTERVAL=60

# Standard logging method copied from 65 script
function log {
    echo "$(date -Iseconds | cut -d'+' -f1): ${NAME}[$$]: INFO: $*" \
        >> "/var/log/software.log" 2>&1
}

# Set global variables for the application version and status, log the
# status. The method and sed commands are copied from 65 script
#
# Exit the script softly when the application is not uploaded, or if the
# system command fails
function read_app_info {
    APP_INFO="$( system application-show "$APP_NAME" \
        --column app_version --column status  --format yaml 2>&1 )"
    if [ $? -ne 0 ]; then
        # This script requires system command to work; quit if it
        # doesn't; Most likely cause is that the app is not uploaded
        log "Execution skipped: $APP_NAME information not found:" \
            "[$APP_INFO]"
        exit 0
    fi

    APP_VERSION="$( echo ${APP_INFO} \
        | sed 's/.*app_version:[[:space:]]\(\S*\).*/\1/' )"
    APP_STATUS="$( echo ${APP_INFO} \
        | sed 's/.*status:[[:space:]]\(\S*\).*/\1/' )"

    log "App name: $APP_NAME; version: $APP_VERSION; status: $APP_STATUS"
}

# Wait for one of the specifiec application states.
# Parameter: space separated list of states to wait for.
#
# Returns 0 when a desired state is reached; else 1
function wait_for_states {
    local states="$1"
    local count=0

    # Wait once first, and return on timeout or an anticipated state:
    while [ "$count" -lt "$APP_WAIT_TRIES" ]; do
        sleep "$APP_WAIT_INTERVAL"
        count="$(( count + 1 ))"
        read_app_info
        if [[ " $states " == *" $APP_STATUS "* ]]; then
            return 0
        fi
    done
    return 1
}

# Perform the abort procedure and log the result.
# Returns the result of the system command.
function do_abort {
    local result
    local text

    text="$( system application-abort "$APP_NAME" 2>&1 )"
    result=$?
    if [ $result -ne 0 ]; then
        log "Error when aborting $APP_NAME status $APP_STATUS: [$text]"
    else
        log "Aborting $APP_NAME status $APP_STATUS"
    fi
    return $result
}

# Perform the remove procedure and log the result.
# Returns the result of the system command.
function do_remove {
    local result
    local text

    text="$( system application-remove "$APP_NAME" 2>&1 )"
    result=$?
    if [ $result -ne 0 ]; then
        log "Error when removing $APP_NAME: [$text]"
    else
        log "Removing $APP_NAME application"
    fi
    return $result
}

# Call abort and remove procedures, waiting for each.
# Returns 0 if a desired state is achieved; non-zero otherwise.
function do_abort_and_remove {
    local result
    do_abort
    result=$?
    if [ $result -eq 0 ]; then
        wait_for_states "apply-failed applied"
        # the logic below ignores the result
    else
        read_app_info
    fi
    # A race to abort could result in the app being applied
    # So retest the state.
    if [[ " apply-failed applied " == *" $APP_STATUS "* ]]; then
        do_remove
        result=$?
        if [ $result -eq 0 ]; then
            wait_for_states "uploaded"
            result=$?
        fi
    else
        # ignore the result of abort wait_for_states
        return 1
    fi
    return $result
}


# Assert that the vault server pods are not updated
# Return 0 if the server pods a running the original server version
# Return 1 if any server pod does not comply, or is missing
function assert_pod_versions {
    local replicas
    local jpath
    local pods
    local pod
    local version
    local podcount=0

    replicas="$( kubectl get statefulsets -n "$APP_NS" "$PODS_PREFIX" \
        -o jsonpath='{.spec.replicas}' )"

    jpath='{range .items[*]}{.metadata.name}{" "}{.metadata.labels.vault-version}{"\n"}{end}'
    pods="$( kubectl get pods -n "$APP_NS" -o jsonpath="$jpath" )"
    while read -r pod; do
        if [[ "$pod" =~ ^${PODS_PREFIX}-([0-9])([ ]) ]]; then
            version="$( echo "$pod" | gawk '{print $NF}' )"
            if [ "$version" != "$ORIG_SERVER_VERSION" ]; then
                log "$APP_NAME $pod is version [$version]"
                return 1
            fi
            podcount=$(( podcount + 1 ))
        fi
    done <<<"$pods"

    if [ "$replicas" -ne "$podcount" ]; then
        log "$PODS_PREFIX has $podcount of $replicas pods"
        return 1
    fi

    return 0
}

# Wait for application-update to complete and then remove it
#
# Not really an abort. Trying to abort an updating operation will often
# end in apply-fail during the recovery (abort is registered against
# recovery). This leaves the app with left over resources from the other
# app version. Let it finish updating and then run the removal procedure
function do_update_abort {
    local result

    wait_for_states "applied"
    result=$?
    if [ $result -eq 0 ]; then
        if [[ "$APP_VERSION" == "$SUPPORTED_TO_RELEASE"* ]]; then
            # In this case, the update rolled back on its own
            # Check if any of the vault pods are upgraded
            # If the pods are the old server version then let it be
            assert_pod_versions
            result=$?
            if [ $result -ne 0 ]; then
                # A log is issued, perform the removal
                do_remove
                result=$?
                if [ $result -eq 0 ]; then
                    wait_for_states "uploaded"
                    result=$?
                fi
                # else, let the statemachine retry later
            fi
        else
            # remove the updated application
            do_remove
            result=$?
            if [ $result -eq 0 ]; then
                wait_for_states "uploaded"
                result=$?
            fi
            # else, let the statemachine retry later
        fi
    fi
    # else, let the statemachine retry later

    return $result
}

# The state machine which responds to the current state.
# Application states are copied from sysinv constants.
# Returns 0 if a desired state is achieved; non-zero otherwise.
function ensure_app_not_applied {
    case "$APP_STATUS" in
        # accepted states
        upload-failed | uploaded | uploading | removing)
            log "$APP_NAME app is in a desired state: $APP_STATUS"
            return 0
            ;;
        # abort and remove states
        applying)
            do_abort_and_remove
            return $?
            ;;
        # handle special case updating
        updating)
            do_update_abort
            return $?
            ;;
        # remove states
        applied | apply-failed)
            do_remove
            result=$?
            if [ $result -eq 0 ]; then
                wait_for_states "uploaded"
                result=$?
            fi
            return $?
            ;;
        # unhandled states:
        # missing | remove-failed | inactive | recovering
        # | restore-requested
        *)
            log "Unhandled application state: $APP_STATUS"
            # wait in case the platform changes this
            return 1
            ;;
    esac
}

# Call the state machine to transition the app to uploaded state.
# Repeat REMOVE_TRIES times until success or failure.
# Do not fail the activate-rollback if the desired state is not reached.
function app_action_with_retry {
    local attempts=0

    while [[ "$attempts" -lt "$REMOVE_TRIES" ]]; do
        ensure_app_not_applied
        if [ $? -eq 0 ]; then
            break
        fi

        sleep "$REMOVE_INTERVAL"
        read_app_info
        attempts="$(( attempts + 1 ))"
    done
}

#
# Main
#

log "Script $NAME invoked with from_release = $FROM_RELEASE" \
    "to_release = $TO_RELEASE action = $ACTION"

if [ "$ACTION" != "activate-rollback" ]; then
    log "Execution skipped: action $ACTION"
    exit 0
fi

if [ "$FROM_RELEASE" != "$SUPPORTED_FROM_RELEASE" ]; then
    log "Execution skipped: Not supported from release: $FROM_RELEASE"
    exit 0
fi

if [ "$TO_RELEASE" != "$SUPPORTED_TO_RELEASE" ]; then
    log "Execution skipped: Not supported to release: $TO_RELEASE"
    exit 0
fi

# The action is activate-rollback - remove the application
source /etc/platform/openrc

read_app_info

# omit action if the app version is not the FROM_RELEASE version
if [[ "$APP_VERSION" == "$TO_RELEASE"* ]]; then
    log "Execution skipped: $APP_NAME is version $TO_RELEASE" \
        "(not upgraded)"
elif [[ "$APP_VERSION" == "$FROM_RELEASE"* ]]; then
    app_action_with_retry
else
    log "Execution skipped: $APP_NAME is version $APP_VERSION" \
        "(unknown release)"
fi

exit 0
