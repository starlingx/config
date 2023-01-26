#!/bin/bash
#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
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

PLATFORM_APPLICATION_PATH='/usr/local/share/applications/helm'
RECOVER_RESULT_SLEEP=30
RECOVER_RESULT_ATTEMPTS=30 # ~15 min to recover app
DELETE_RESULT_SLEEP=10
DELETE_RESULT_ATTEMPTS=6   # ~1 min to delete app
UPLOAD_RESULT_SLEEP=10
UPLOAD_RESULT_ATTEMPTS=24  # ~4 min to upload app
UPDATE_RESULT_SLEEP=30
UPDATE_RESULT_ATTEMPTS=30  # ~15 min to update app

# This will log to /var/log/platform.log
function log {
    logger -p local1.info $1
}

function verify_apps_are_not_recovering {
    # Scrape app names. Skip header and footer.
    APPS=$(system application-list --nowrap | head -n-1 | tail -n+4 | awk '{print $2}')
    for a in ${APPS}; do
        APP_STATUS=$(system application-show $a --column status --format value)
        if [[ "${APP_STATUS}" =~ ^(applying|restore-requested)$ ]]; then
            if [ ${system_type} == 'All-in-one' ] && [ ${system_mode} == 'simplex' ]; then
                log "$NAME: $a is in a recovering state: ${APP_STATUS}. Waiting for all applications to be uploaded or applied."
                return 1
            else
                log "$NAME: $a is in an unexpected state: ${APP_STATUS}. Exiting for manual intervention..."
            fi
            exit 1
        fi
    done
    return 0
}

log "$NAME: Starting Kubernetes application updates from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"

if [ "$ACTION" == "activate" ]; then
    # TODO: double check the inclusive condition.
    if [ "$TO_RELEASE" != "22.12" ]; then
        log "not upgrading to 22.12, skip"
        exit 0
    fi

    # move the costly source command in the if branch, so only execute when needed.
    source /etc/platform/openrc
    source /etc/platform/platform.conf

    for tries in $(seq 1 $RECOVER_RESULT_ATTEMPTS); do
        if verify_apps_are_not_recovering; then
            break
        elif [ $tries == $RECOVER_RESULT_ATTEMPTS ]; then
            log "$NAME: Exceeded maximum application recovery time of $(date -u -d @"$((RECOVER_RESULT_ATTEMPTS*RECOVER_RESULT_SLEEP))" +"%Mm%Ss"). Execute upgrade-activate again when all applications are uploaded or applied."
            exit 1
        fi
        sleep $RECOVER_RESULT_SLEEP
    done

    # Get the list of applications installed in the new release
    for fqpn_app in $PLATFORM_APPLICATION_PATH/*; do
        # Extract the app name and version from the tarball name: app_name-version.tgz
        re='^(.*)-([0-9]+\.[0-9]+-[0-9]+).tgz'
        [[ "$(basename $fqpn_app)" =~ $re ]]
        UPGRADE_APP_NAME=${BASH_REMATCH[1]}
        UPGRADE_APP_VERSION=${BASH_REMATCH[2]}
        log "$NAME: Found application ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION} at $fqpn_app"

        # Confirm application is upgradable
        # TODO: move nginx back to the supported platform applications list when
        #       fluxcd application upgrade is supported
        if [[ "${UPGRADE_APP_NAME}" =~ ^(platform-integ-apps|nginx-ingress-controller|snmp|metrics-server|auditd|ptp-notification|istio)$ ]]; then
            log "$NAME: ${UPGRADE_APP_NAME} is a supported platform application."
        elif [[ "${UPGRADE_APP_NAME}" =~ ^(cert-manager|oidc-auth-apps)$ && ( "$FROM_RELEASE" == "22.06" || "$FROM_RELEASE" == "21.12" ) ]]; then
            log "$NAME: ${UPGRADE_APP_NAME} is a supported platform application from $FROM_RELEASE."
        elif [[ "${UPGRADE_APP_NAME}" =~ ^(cert-manager|oidc-auth-apps)$ ]]; then
            log "$NAME: ${UPGRADE_APP_NAME} is handled by another script."
            continue
        else
            log "$NAME: ${UPGRADE_APP_NAME} is not a supported platform application. skipping..."
            continue
        fi

        # Confirm application is loaded.
        EXISTING_APP_NAME=$(system application-show $UPGRADE_APP_NAME --column name --format value)
        if [ -z "${EXISTING_APP_NAME}" ]; then
            log "$NAME: ${UPGRADE_APP_NAME} is currently not uploaded in the system. skipping..."
            continue
        fi

        # Get the existing application details
        EXISTING_APP_INFO=$(system application-show $EXISTING_APP_NAME --column app_version --column status --format yaml)
        EXISTING_APP_VERSION=$(echo ${EXISTING_APP_INFO} | sed 's/.*app_version:[[:space:]]\(\S*\).*/\1/')
        EXISTING_APP_STATUS=$(echo ${EXISTING_APP_INFO} | sed 's/.*status:[[:space:]]\(\S*\).*/\1/')

        log "$NAME: $EXISTING_APP_NAME, version $EXISTING_APP_VERSION, is currently in the state: $EXISTING_APP_STATUS"

        if [ "x${UPGRADE_APP_VERSION}" == "x${EXISTING_APP_VERSION}" ]; then
            # If the app is in uploaded or applied state, then we continue with next iteration.
            # Else, the code execution proceeds and the script would exit with an unexpected state.
            if [[ "${EXISTING_APP_STATUS}" =~ ^(uploaded|applied)$ ]]; then
                log "$NAME: ${UPGRADE_APP_NAME}, version ${EXISTING_APP_VERSION}, is already present. skipping..."
                continue
            fi
        fi

        # All applications should be in an 'applied' or 'uploaded' state. Any other state is unexpected
        case "${EXISTING_APP_STATUS}" in

            # States that are upgradable
            uploaded)
                log "$NAME: Deleting ${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}"
                system application-delete ${EXISTING_APP_NAME}

                # Wait on the delete, should be quick
                for tries in $(seq 1 $DELETE_RESULT_ATTEMPTS); do
                    EXISTING_APP_STATUS=$(system application-show $EXISTING_APP_NAME --column status --format value)
                    if [ -z "${EXISTING_APP_STATUS}" ]; then
                        log "$NAME: ${EXISTING_APP_NAME} has been deleted."
                        break
                    fi
                    sleep $DELETE_RESULT_SLEEP
                done

                if [ $tries == $DELETE_RESULT_ATTEMPTS ]; then
                    log "$NAME: ${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}, was not deleted in the alloted time. Exiting for manual intervention..."
                    exit 1
                fi

                log "$NAME: Uploading ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION} from $fqpn_app"
                system application-upload $fqpn_app
                # Wait on the upload, should be quick
                for tries in $(seq 1 $UPLOAD_RESULT_ATTEMPTS); do
                    UPGRADE_APP_STATUS=$(system application-show $UPGRADE_APP_NAME --column status --format value)
                    if [ "${UPGRADE_APP_STATUS}" == 'uploaded' ]; then
                        log "$NAME: ${UPGRADE_APP_NAME} has been uploaded."
                        break
                    fi
                    sleep $UPLOAD_RESULT_SLEEP
                done

                if [ $tries == $UPLOAD_RESULT_ATTEMPTS ]; then
                    log "$NAME: ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION}, was not uploaded in the alloted time. Exiting for manual intervention..."
                    exit 1
                fi

                ;;

            applied)
                log "$NAME: Updating ${EXISTING_APP_NAME}, from version ${EXISTING_APP_VERSION} to version ${UPGRADE_APP_VERSION} from $fqpn_app"
                system application-update $fqpn_app
                # Wait on the upload, should be quick
                for tries in $(seq 1 $UPDATE_RESULT_ATTEMPTS); do
                    UPDATING_APP_INFO=$(system application-show $UPGRADE_APP_NAME --column name --column app_version --column status --format yaml)
                    UPDATING_APP_NAME=$(echo ${UPDATING_APP_INFO} | sed 's/.*name:[[:space:]]\(\S*\).*/\1/')
                    UPDATING_APP_VERSION=$(echo ${UPDATING_APP_INFO} | sed 's/.*app_version:[[:space:]]\(\S*\).*/\1/')
                    UPDATING_APP_STATUS=$(echo ${UPDATING_APP_INFO} | sed 's/.*status:[[:space:]]\(\S*\).*/\1/')

                    if [ "${UPDATING_APP_NAME}" == "${UPGRADE_APP_NAME}" ] && \
                       [ "${UPDATING_APP_VERSION}" == "${UPGRADE_APP_VERSION}" ] && \
                       [ "${UPDATING_APP_STATUS}" == "applied" ]; then
                        ALARMS=$(fm alarm-list --nowrap --uuid --query "alarm_id=750.005;entity_type_id=k8s_application;entity_instance_id=${UPGRADE_APP_NAME}" | head -n-1 | tail -n+4 | awk '{print $2}')
                        for alarm in ${ALARMS}; do
                            log "$NAME: [Warning] A stale 750.005 Application Update In Progress alarm was found for ${UPGRADE_APP_NAME}. Clearing it (UUID: ${alarm})."
                            fm alarm-delete $alarm
                        done
                        log "$NAME: ${UPGRADE_APP_NAME} has been updated to version ${UPGRADE_APP_VERSION} from version ${EXISTING_APP_VERSION}"
                        break
                    fi
                    sleep $UPDATE_RESULT_SLEEP
                done

                if [ $tries == $UPDATE_RESULT_ATTEMPTS ]; then
                    log "$NAME: ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION}, was not updated in the alloted time. Exiting for manual intervention..."
                    exit 1
                fi

                if [ $tries != $UPDATE_RESULT_ATTEMPTS ] && [ "${UPDATING_APP_VERSION}" == "${EXISTING_APP_VERSION}" ] ; then
                    log "$NAME: ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION}, update failed and was rolled back. Exiting for manual intervention..."
                    exit 1
                fi
                ;;

            # States that are unexpected
            uploading | upload-failed | applying | apply-failed | removing | remove-failed | restore-requested | updating | recovering )
                log "$NAME: ${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}, is in an unexpected state: ${EXISTING_APP_STATUS}. Exiting for manual intervention..."
                exit 1
                ;;

            *)
                log "$NAME: ${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}, is in an unknown state: ${EXISTING_APP_STATUS}. Exiting for manual intervention..."
                exit 1
                ;;
        esac

    done

    log "$NAME: Completed Kubernetes application updates for release $FROM_RELEASE to $TO_RELEASE with action $ACTION"
else
    log "$NAME: No actions required for from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"
fi


exit 0
