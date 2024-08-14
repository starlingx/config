#!/bin/bash
#
# Copyright (c) 2020-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# This migration script is used for upgrading platform applications during the
# activate stage of a platform upgrade. It will:
# - Ignore any new applications that are installed in the To-Release and rely on
#   any platform-managed application logic to upload/apply it after the upgrade
#   has completed.
# - Attempt to delete and upload any apps that were in the uploaded state in the
#   From-Release if the version has changed in the To-Release
# - Attempt to update any app that was in the applied state in the From-Release
#   if the version has changed in the To-Release

NAME=$(basename $0)

# The migration scripts are passed these parameters:
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

if (( $# != 3 && $# != 4 )); then
    >&2 echo "Error: Missing Arguments!"
    >&2 echo "Usage: 65-k8s-app-upgrade.sh FROM_RELEASE TO_RELEASE ACTION"
    >&2 echo "Exiting for manual intervention..."
    exit 1
fi

UPGRADE_IN_PROGRESS_APPS_FILE='/etc/platform/.upgrade_in_progress_apps'

RECOVER_RESULT_SLEEP=30
RECOVER_RESULT_ATTEMPTS=30 # ~15 min to recover app
DELETE_RESULT_SLEEP=10
DELETE_RESULT_ATTEMPTS=6   # ~1 min to delete app
UPLOAD_RESULT_SLEEP=10
UPLOAD_RESULT_ATTEMPTS=24  # ~4 min to upload app
UPDATE_RESULT_SLEEP=30
UPDATE_RESULT_ATTEMPTS=30  # ~15 min to update app
COMMAND_RETRY_SLEEP=30
COMMAND_RETRY_ATTEMPTS=10  # ~5 min to wait on a retried command.
SOFTWARE_LOG_PATH='/var/log/software.log'

function log {
    echo "$(date -Iseconds | cut -d'+' -f1): ${NAME}[$$]: INFO: $*" >> "$SOFTWARE_LOG_PATH" 2>&1
}

function verify_apps_are_not_recovering {
    # Scrape app names. Skip header and footer.
    APPS=$(system application-list --nowrap | head -n-1 | tail -n+4 | awk '{print $2}')
    for a in ${APPS}; do
        # If app is being upgraded then ignore
        if grep -q $a $UPGRADE_IN_PROGRESS_APPS_FILE; then
            continue
        fi

        APP_STATUS=$(system application-show $a --column status --format value)
        if [[ "${APP_STATUS}" =~ ^(applying|restore-requested)$ ]]; then
            if [ ${system_type} == 'All-in-one' ] && [ ${system_mode} == 'simplex' ]; then
                log "$a is in a recovering state: ${APP_STATUS}. Waiting for all applications to be uploaded or applied."
                return 1
            else
                log "$a is in an unexpected state: ${APP_STATUS}. Exiting for manual intervention..."
            fi
            exit 1
        fi
    done
    return 0
}

function retry_command {
    # This command attempts to retry the command provided and waits to see if it
    # executed sucessfully or failed.

    COMMAND=$1
    APPLICATION_NAME=$2

    if (( $# != 2 )); then
        >&2 echo "Error: Missing Arguments!"
        >&2 echo "Usage: retry_command COMMAND APPLICATION_NAME"
        >&2 echo "Exiting for manual intervention..."
        exit 1
    fi

    log "Retrying command: ${COMMAND}"

    system ${COMMAND} ${APPLICATION_NAME}

    # Do an initial sleep before first status check attempt
    sleep $COMMAND_RETRY_SLEEP

    for tries in $(seq 1 $COMMAND_RETRY_ATTEMPTS); do

        APP_STATUS=$(system application-show ${APPLICATION_NAME} --column status --format value)

        if [[ "${APP_STATUS}" =~ ^(uploaded|applied|removed)$ ]]; then
            # This is if the command succeeded, break here.
            log "${APPLICATION_NAME} status is: ${APP_STATUS}. Done!"
            break
        elif [[ "${APP_STATUS}" =~ ^(upload-failed|apply-failed|remove-failed)$ ]]; then
            # The command was retried, but resulted in another failure.  Nothing more to be done,
            # so exit.
            log "${APPLICATION_NAME} status is: ${APP_STATUS}. The retry has failed. Exiting for manual intervention..."
            exit 1
        elif [ $tries == $COMMAND_RETRY_ATTEMPTS ]; then
            log "Exceeded maximum application ${COMMAND} time of $(date -u -d @"$((COMMAND_RETRY_ATTEMPTS*COMMAND_RETRY_SLEEP))" +"%Mm%Ss"). Execute upgrade-activate again when all applications are uploaded or applied."
            exit 1
        fi
        log "${APPLICATION_NAME} status is: ${APP_STATUS}. Will check again in ${COMMAND_RETRY_SLEEP} seconds."
        sleep $COMMAND_RETRY_SLEEP
    done

    log "Retrying command: ${COMMAND} - Succeeded!"
    return 0
}

log "Starting Kubernetes application updates from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"

if [ "$ACTION" == "activate" ]; then
    # remove upgrade in progress file
    [[ -f $UPGRADE_IN_PROGRESS_APPS_FILE ]] && rm -f $UPGRADE_IN_PROGRESS_APPS_FILE

    # move the costly source command in the if branch, so only execute when needed.
    source /etc/platform/openrc
    source /etc/platform/platform.conf

    for tries in $(seq 1 $RECOVER_RESULT_ATTEMPTS); do
        if verify_apps_are_not_recovering; then
            break
        elif [ $tries == $RECOVER_RESULT_ATTEMPTS ]; then
            log "Exceeded maximum application recovery time of $(date -u -d @"$((RECOVER_RESULT_ATTEMPTS*RECOVER_RESULT_SLEEP))" +"%Mm%Ss"). Execute upgrade-activate again when all applications are uploaded or applied."
            exit 1
        fi
        sleep $RECOVER_RESULT_SLEEP
    done

    # Get the current k8s version
    K8S_VERSIONS=$(system kube-version-list)
    ACTIVE_K8S_VERSION=$(echo "$K8S_VERSIONS" | grep ' True ' | grep ' active ' | awk -F '|' '{print $2}' | tr -d ' ')

    # Get compatibles apps with current k8s version

    # TODO(dbarbosa): Remove "--log-file /var/log/software.log" after fixing the issue with logs of
    # the "sysinv-app query <k8s-target-version>" being logged to stdout.
    COMPATIBLES_APPS=$(sudo sysinv-app --log-file ${SOFTWARE_LOG_PATH} query ${ACTIVE_K8S_VERSION})
    COMPATIBLES_APPS_FORMATED=$(echo "$COMPATIBLES_APPS" | paste -sd '|')

    # Get all loads apps
    APPS_LOADED=$(system application-list | head -n-1 | tail -n+4 | awk '{print $2}')

    # Check and log compatible and not compatible apps
    for APP in $APPS_LOADED; do
        if [[ "${APP}" =~ (${COMPATIBLES_APPS_FORMATED}) ]]; then
            log "${APP} has an upgrade compatible tarball and will be updated."
        else
            log "${APP} does not have an upgrade compatible tarball and will remain at its current version."
            continue
        fi
    done

    # Get compatibles tarballs path with current k8s version
    # Sort applications by version. Lower versions are attempted first.

    # TODO(dbarbosa): Remove "--log-file /var/log/software.log" after fixing the issue with logs of
    # the "sysinv-app query <k8s-target-version>" being logged to stdout.
    COMPATIBLES_APPS_TARBALL_PATH=$(sudo sysinv-app --log-file ${SOFTWARE_LOG_PATH} query ${ACTIVE_K8S_VERSION} --include-path | sort -V)

    LAST_APP_CHECKED=""
    # Get the list of applications installed in the new release
    for fqpn_app in $COMPATIBLES_APPS_TARBALL_PATH; do
        # Extract the app name and version from the tarball name: app_name-version.tgz
        re='^(.*)-([0-9]+\.[0-9]+-[0-9]+).tgz'
        [[ "$(basename $fqpn_app)" =~ $re ]]
        UPGRADE_APP_NAME=${BASH_REMATCH[1]}
        UPGRADE_APP_VERSION=${BASH_REMATCH[2]}
        log "Found application ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION} at $fqpn_app"

        # Confirm application is loaded.
        EXISTING_APP_NAME=$(system application-show $UPGRADE_APP_NAME --column name --format value)
        if [ -z "${EXISTING_APP_NAME}" ]; then
            log "${UPGRADE_APP_NAME} is currently not uploaded in the system. skipping..."
            continue
        fi

        # If the last iteration for the same app was sucessful no further updates are necessary
        if [ "${LAST_APP_CHECKED}" == "${UPGRADE_APP_NAME}" ] && [[ "${EXISTING_APP_STATUS}" =~ ^(uploaded|applied)$ ]]; then
            continue
        fi

        # Get the existing application details
        EXISTING_APP_INFO=$(system application-show $EXISTING_APP_NAME --column app_version --column status --format yaml)
        EXISTING_APP_VERSION=$(echo ${EXISTING_APP_INFO} | sed 's/.*app_version:[[:space:]]\(\S*\).*/\1/')
        EXISTING_APP_STATUS=$(echo ${EXISTING_APP_INFO} | sed 's/.*status:[[:space:]]\(\S*\).*/\1/')

        log "$EXISTING_APP_NAME, version $EXISTING_APP_VERSION, is currently in the state: $EXISTING_APP_STATUS"

        if [ "x${UPGRADE_APP_VERSION}" == "x${EXISTING_APP_VERSION}" ]; then
            # If the app is in uploaded or applied state, then we continue with next iteration.
            # Else, the code execution proceeds and the script would exit with an unexpected state.
            if [[ "${EXISTING_APP_STATUS}" =~ ^(uploaded|applied)$ ]]; then
                log "${UPGRADE_APP_NAME}, version ${EXISTING_APP_VERSION}, is already present. Skipping..."
                continue
            fi
        fi

        # All applications should be in an 'applied' or 'uploaded' state. Any other state is unexpected
        case "${EXISTING_APP_STATUS}" in

            # States that are upgradable
            uploaded)
                log "Deleting ${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}"
                system application-delete ${EXISTING_APP_NAME}

                # Wait on the delete, should be quick
                for tries in $(seq 1 $DELETE_RESULT_ATTEMPTS); do
                    EXISTING_APP_STATUS=$(system application-show $EXISTING_APP_NAME --column status --format value)
                    if [ -z "${EXISTING_APP_STATUS}" ]; then
                        log "${EXISTING_APP_NAME} has been deleted."
                        break
                    fi
                    sleep $DELETE_RESULT_SLEEP
                done

                if [ $tries == $DELETE_RESULT_ATTEMPTS ]; then
                    log "${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}, was not deleted in the alloted time. Exiting for manual intervention..."
                    exit 1
                fi

                log "Uploading ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION} from $fqpn_app"
                system application-upload $fqpn_app
                ;;

            applied)
                log "Updating ${EXISTING_APP_NAME}, from version ${EXISTING_APP_VERSION} to version ${UPGRADE_APP_VERSION} from $fqpn_app"
                system application-update $fqpn_app
                ;;

            upload-failed)
                log "${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}, upload failed: ${EXISTING_APP_STATUS}. Retrying command..."
                retry_command "application-upload" "${EXISTING_APP_NAME}"
                ;;

            apply-failed)
                log "${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}, apply failed: ${EXISTING_APP_STATUS}. Retrying command..."
                retry_command "application-apply" "${EXISTING_APP_NAME}"
                ;;

            remove-failed)
                log "${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}, remove failed: ${EXISTING_APP_STATUS}. Retrying command..."
                retry_command "application-remove" "${EXISTING_APP_NAME}"
                ;;

            # States that are unexpected
            uploading | applying | removing | restore-requested | updating | recovering)
                log "${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}, is in an unexpected state: ${EXISTING_APP_STATUS}. Exiting for manual intervention..."
                exit 1
                ;;

            *)
                log "${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}, is in an unknown state: ${EXISTING_APP_STATUS}. Exiting for manual intervention..."
                exit 1
                ;;
        esac

        # Include app in upgrade in progress file
        if ! grep -q "${EXISTING_APP_NAME},${EXISTING_APP_VERSION},${UPGRADE_APP_VERSION}" $UPGRADE_IN_PROGRESS_APPS_FILE; then
            echo "${EXISTING_APP_NAME},${EXISTING_APP_VERSION},${UPGRADE_APP_VERSION}" >> $UPGRADE_IN_PROGRESS_APPS_FILE
        fi

        LAST_APP_CHECKED=${UPGRADE_APP_NAME}
    done

    log "Completed Kubernetes application updates for release $FROM_RELEASE to $TO_RELEASE with action $ACTION"
else
    log "No actions required for from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"
fi


exit 0
