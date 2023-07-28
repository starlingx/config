#!/bin/bash
#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# This migration script is used to wait for apps that were upgraded by
# previous application upgrade scripts on the chain. It will:
# - Wait for upgraded applications to be either 'applied' or 'uploaded'
#   with the new version, these applications must be stored earlier during
#   upgrade-activate process in a file inside /etc/platform/

NAME=$(basename $0)

# The migration scripts are passed these parameters:
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

CONFIG_PERMDIR="/opt/platform/config/${TO_RELEASE}"
UPGRADE_IN_PROGRESS_APPS_FILE='/etc/platform/.upgrade_in_progress_apps'
UPDATE_RESULT_SLEEP=30
UPDATE_RESULT_ATTEMPTS=30  # ~15 min to update app

# This will log to /var/log/platform.log
function log {
    logger -p local1.info $1
}

log "$NAME: Starting application upgrade watcher script from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"

if [ "$ACTION" == "activate" ]; then

    # move the costly source command in the if branch, so only execute when needed.
    source /etc/platform/openrc
    source /etc/platform/platform.conf

    if [ ! -f $UPGRADE_IN_PROGRESS_APPS_FILE ]; then
        log "$NAME: No file with application upgrade in progress found, skipping script."
        exit 0
    fi

    # Loop over upgraded apps and wait them to become 'applied' or 'uploaded' with the new version
    APPS_LIST=$(cat $UPGRADE_IN_PROGRESS_APPS_FILE)
    for tries in $(seq 1 $UPDATE_RESULT_ATTEMPTS); do
        log "$NAME: Checking applications status... Retry ${tries} of ${UPDATE_RESULT_ATTEMPTS}"
        ALL_UPGRADED="true"
        UPGRADE_IN_PROGRESS_APPS_LIST=""
        for app in $APPS_LIST; do
            re='[[:space:]]*(\S*),(\S*),(\S*)[[:space:]]*'
            [[ $app =~ $re ]]
            UPGRADE_APP_NAME=${BASH_REMATCH[1]}
            EXISTING_APP_VERSION=${BASH_REMATCH[2]}
            UPGRADE_APP_VERSION=${BASH_REMATCH[3]}

            UPDATING_APP_INFO=$(system application-show $UPGRADE_APP_NAME --column name --column app_version --column status --format yaml)
            UPDATING_APP_NAME=$(echo ${UPDATING_APP_INFO} | sed 's/.*name:[[:space:]]\(\S*\).*/\1/')
            UPDATING_APP_VERSION=$(echo ${UPDATING_APP_INFO} | sed 's/.*app_version:[[:space:]]\(\S*\).*/\1/')
            UPDATING_APP_STATUS=$(echo ${UPDATING_APP_INFO} | sed 's/.*status:[[:space:]]\(\S*\).*/\1/')

            if [ "${UPDATING_APP_NAME}" == "${UPGRADE_APP_NAME}" ] && \
               [ "${UPDATING_APP_VERSION}" == "${UPGRADE_APP_VERSION}" ]; then
                case "${UPDATING_APP_STATUS}" in
                    "applied"|"uploaded")
                        ALARMS=$(fm alarm-list --nowrap --uuid --query "alarm_id=750.005;entity_type_id=k8s_application;entity_instance_id=${UPGRADE_APP_NAME}" | head -n-1 | tail -n+4 | awk '{print $2}')
                        for alarm in ${ALARMS}; do
                            log "$NAME: WARN: A stale 750.005 Application Update In Progress alarm was found for ${UPGRADE_APP_NAME}. Clearing it (UUID: ${alarm})."
                            fm alarm-delete $alarm
                        done
                        log "$NAME: ${UPGRADE_APP_NAME} has been updated to version ${UPGRADE_APP_VERSION} from version ${EXISTING_APP_VERSION}"
                        ;;
                    *)
                        log "$NAME: ${UPGRADE_APP_NAME} update in progress to version ${UPGRADE_APP_VERSION} from version ${EXISTING_APP_VERSION}"
                        UPGRADE_IN_PROGRESS_APPS_LIST="${app} ${UPGRADE_IN_PROGRESS_APPS_LIST}"
                        ALL_UPGRADED="false"
                        ;;
                esac
            else
                log "$NAME: WARN: ${UPGRADE_APP_NAME} is on '${UPDATING_APP_STATUS}' state but the version is not updated to ${UPGRADE_APP_VERSION} from version ${EXISTING_APP_VERSION}"
                UPGRADE_IN_PROGRESS_APPS_LIST="${app} ${UPGRADE_IN_PROGRESS_APPS_LIST}"
                ALL_UPGRADED="false"
            fi
        done

        # Exit loop if all applications are upgraded
        [[ $ALL_UPGRADED == "true" ]] && break

        # Next iteration will check only apps which upgrade is in progress
        APPS_LIST=$UPGRADE_IN_PROGRESS_APPS_LIST

        sleep $UPDATE_RESULT_SLEEP
    done

    if [ $tries == $UPDATE_RESULT_ATTEMPTS ]; then
        log "$NAME: One or more apps (${APPS_LIST// /, }) were not updated in the alloted time. Exiting for manual intervention..."
        exit 1
    fi

    # remove upgrade in progress file
    log "$NAME: Removing temporary file: $UPGRADE_IN_PROGRESS_APPS_FILE"
    [[ -f $UPGRADE_IN_PROGRESS_APPS_FILE ]] && rm -f $UPGRADE_IN_PROGRESS_APPS_FILE

    log "$NAME: Completed application upgrade watcher script from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"
else
    log "$NAME: No actions required for from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"
fi
