#!/bin/bash
#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This migration script is used for replacing an app during the
# activate stage of a platform upgrade. The app is not otherwise
# handled by 65-k8s-app-upgrade.sh.  The code will:
# - remove the old app version
# - run app specific code with is inserted into the script
# - apply the new app version
#
# The script is based on 64-upgrade-cert-manager.sh.  Logic for
# determining application versions is copied from 65-k8s-app-upgrade.sh
# application upgrade script in order to keep things consistent.
#
# This script is intended initially as a generic template.
#
# The current copy is writen for oidc-auth-apps

# The migration scripts are passed these parameters:
NAME=$(basename $0)
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

# only run this script during upgrade-activate
if [ "$ACTION" != "activate" ]; then
    exit 0
fi

# only run if from 21.12 release
if [ "$FROM_RELEASE" != "21.12" ]; then
    exit 0
fi

PLATFORM_APPLICATION_PATH='/usr/local/share/applications/helm'
PATH=$PATH:/usr/local/sbin

# conversion script; this script will convert the helm overrides
# reading from postgres and putting overrides into /opt/oidc-auth-apps
CONV_SCRIPT='/etc/upgrade.d/50-validate-oidc-auth-apps.py'
CONV_PARAMS="$FROM_RELEASE $TO_RELEASE migrate"

DELETE_RESULT_SLEEP=10
DELETE_RESULT_ATTEMPTS=6   # ~1 min to delete app
UPLOAD_RESULT_SLEEP=10
UPLOAD_RESULT_ATTEMPTS=24  # ~4 min to upload app
APPLY_RESULT_SLEEP=30
APPLY_RESULT_ATTEMPTS=30  # ~15 min to update app
REMOVE_RESULT_SLEEP=10
REMOVE_RESULT_ATTEMPTS=48 # ~8 min to remove app

source /etc/platform/openrc
source /etc/platform/platform.conf

# This will log to /var/log/platform.log
function log {
    logger -p local1.info $1
}

EXISTING_APP_NAME='oidc-auth-apps'
EXISTING_APP_INFO=$(system application-show $EXISTING_APP_NAME --column app_version --column status --format yaml)
EXISTING_APP_VERSION=$(echo ${EXISTING_APP_INFO} | sed 's/.*app_version:[[:space:]]\(\S*\).*/\1/')
EXISTING_APP_STATUS=$(echo ${EXISTING_APP_INFO} | sed 's/.*status:[[:space:]]\(\S*\).*/\1/')
ORIGINAL_APP_STATUS=$EXISTING_APP_STATUS

# oidc-auth-apps has user overrides converted and saved for
# re-apply at this time
OIDC_OVERRIDES="/opt/oidc-auth-apps/converted"
OIDC_CHARTS="dex oidc-client secret-observer"
function oidc_specific_handling {
    for chart in $OIDC_CHARTS; do
        chart_f="${OIDC_OVERRIDES}/${chart}_user_overrides.yaml"
        if [ ! -f "$chart_f" ]; then
            continue
        fi
        system helm-override-update oidc-auth-apps "${chart}" kube-system \
            --values="${chart_f}" \
        || return 1
    done
}

# Extract the app name and version from the tarball name: app_name-version.tgz
UPGRADE_TARBALL="$(find $PLATFORM_APPLICATION_PATH -name "${EXISTING_APP_NAME}*.tgz")"
filecount="$( echo "$UPGRADE_TARBALL" | wc -w )"
if [ -z "$UPGRADE_TARBALL" -o "$filecount" -ne 1 ]; then
    log "$NAME: ${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}, upgrade tarball not found (${filecount}).  Exiting for manual intervention..."
    exit 1
fi

re='^('${EXISTING_APP_NAME}')-([0-9]+\.[0-9]+-[0-9]+).tgz'
[[ "$(basename $UPGRADE_TARBALL)" =~ $re ]]
UPGRADE_APP_NAME=${BASH_REMATCH[1]}
UPGRADE_APP_VERSION=${BASH_REMATCH[2]}

# Accept the application in the following states
ACCEPTED_STATES="applied uploaded"
if [[ " $ACCEPTED_STATES " != *" $EXISTING_APP_STATUS "* ]]; then
    log "$NAME: ${UPGRADE_APP_NAME}, version ${EXISTING_APP_VERSION}, in bad state ${EXISTING_APP_STATUS}. Exiting for manual intervention..."
    exit 1
fi

# assuming application is in applied state, but log it anyways
log "$NAME: $EXISTING_APP_NAME, version $EXISTING_APP_VERSION, is currently in the state: $EXISTING_APP_STATUS"

# only upgrade the application if the versions dont match
# in case the upgrade activate failed due to other reasons, and this
# is not the first time this script is run
if [ "x${UPGRADE_APP_VERSION}" == "x${EXISTING_APP_VERSION}" ]; then
    log "$NAME: $UPGRADE_APP_NAME, version $UPGRADE_APP_VERSION, is the same."
    exit 0
else
    # The 50-validate-oidc-auth-apps.py is used to convert helm
    # overrides.  Run it here on the active controller during
    # uprade-activate
    su postgres -c "$CONV_SCRIPT $CONV_PARAMS"

    if [ "$ORIGINAL_APP_STATUS" != "uploaded" ]; then
        # remove old app version
        log "$NAME: Removing ${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}"
        system application-remove -f ${EXISTING_APP_NAME}

        # Wait on the remove, should be somewhat quick
        for tries in $(seq 1 $REMOVE_RESULT_ATTEMPTS); do
            EXISTING_APP_STATUS=$(system application-show $EXISTING_APP_NAME --column status --format value)
            if [ "${EXISTING_APP_STATUS}" == 'uploaded' ]; then
                log "$NAME: ${EXISTING_APP_NAME} has been removed."
                break
            fi
            sleep $REMOVE_RESULT_SLEEP
        done

        if [ $tries == $REMOVE_RESULT_ATTEMPTS ]; then
            log "$NAME: ${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}, was not removed in the allocated time. Exiting for manual intervention..."
            exit 1
        fi
    fi

    # delete old app
    log "$NAME: Deleting ${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}"
    system application-delete -f ${EXISTING_APP_NAME}

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
        log "$NAME: ${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}, was not deleted in the allocated time. Exiting for manual intervention..."
        exit 1
    fi

    # upload new app version
    log "$NAME: Uploading ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION} from $UPGRADE_TARBALL"
    system application-upload $UPGRADE_TARBALL
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
        log "$NAME: ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION}, was not uploaded in the allocated time. Exiting for manual intervention..."
        exit 1
    fi

    if [ ! -d "$OIDC_OVERRIDES" ]; then
        # this is a soft error, the upgrades procedure should not
        # be affected by the absence of helm-overrides. Either the
        # application is not configured, or the conversion of overrides
        # was not possible
        log "$NAME: ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION}, no helm overrides to set.  Upgrade of ${UPGRADE_APP_NAME} complete."
        exit 0
    fi
    oidc_specific_handling
    if [ $? -ne 0 ]; then
        log "$NAME: ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION}, Helm overrides not set. Exiting for manual intervention..."
        if [ "$ORIGINAL_APP_STATUS" == "uploaded" ]; then
            # the application that is not applied does not interfere
            exit 0
        else
            exit 1
        fi
    fi

    if [ "$ORIGINAL_APP_STATUS" == "uploaded" ]; then
        log "$NAME: ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION}: upload complete"
        exit 0
    fi

    # dex won't apply without overrides, do not try
    if [ ! -f "${OIDC_OVERRIDES}/dex_user_overrides.yaml" ]; then
        log "$NAME: ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION}: dex does not have overrides"
        exit 0
    fi

    # apply new app version
    log "$NAME: Applying ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION}"
    system application-apply ${UPGRADE_APP_NAME}

    # Wait on the apply
    for tries in $(seq 1 $APPLY_RESULT_ATTEMPTS); do
        UPGRADE_APP_STATUS=$(system application-show $UPGRADE_APP_NAME --column status --format value)
        if [ "${UPGRADE_APP_STATUS}" == 'applied' ]; then
            log "$NAME: ${UPGRADE_APP_NAME} has been applied."
            break
        fi
        sleep $APPLY_RESULT_SLEEP
    done

    if [ $tries == $APPLY_RESULT_ATTEMPTS ]; then
        log "$NAME: ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION}, was not applied in the allocated time. Exiting for manual intervention..."
        exit 1
    fi
fi

exit 0
