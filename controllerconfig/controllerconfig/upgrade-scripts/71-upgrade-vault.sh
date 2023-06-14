#!/bin/bash
#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This migration script is used for replacing an app during the
# activate stage of a platform upgrade. The app is not otherwise
# handled by 65-k8s-app-upgrade.sh.  The code will:
# - remove the old app version
# - run app specific code inserted into this script
# - apply the new app version
#
# The script is based on 64-upgrade-cert-manager.sh.  Logic for
# determining application versions is copied from 65-k8s-app-upgrade.sh
# application upgrade script in order to keep things consistent.
#
# This script is intended initially as a generic template.
#
# The current copy is written for vault

# The migration scripts are passed these parameters:
NAME=$(basename $0)
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

STATE_APPLIED="applied"
STATE_UPLOADED="uploaded"

ACCEPTED_ACTION="activate"
ACCEPTED_FROM="21.12"
ACCEPTED_TO="22.12"

EXISTING_APP_NAME='vault'

DELETE_RESULT_SLEEP=10
DELETE_RESULT_ATTEMPTS=6   # ~1 min to delete app
UPLOAD_RESULT_SLEEP=10
UPLOAD_RESULT_ATTEMPTS=24  # ~4 min to upload app
APPLY_RESULT_SLEEP=30
APPLY_RESULT_ATTEMPTS=30  # ~15 min to update app
REMOVE_RESULT_SLEEP=10
REMOVE_RESULT_ATTEMPTS=48 # ~8 min to remove app

PLATFORM_APPLICATION_PATH='/usr/local/share/applications/helm'
UPGRADE_IN_PROGRESS_APPS_FILE='/etc/platform/.upgrade_in_progress_apps'
PATH=$PATH:/usr/local/sbin

source /etc/platform/openrc
source /etc/platform/platform.conf

# This will log to /var/log/platform.log
function log {
    logger -p local1.info $1
}

# only run this script during upgrade-activate
if [ "${ACTION}" != "${ACCEPTED_ACTION}" ]; then
    log "$NAME: omit upgrade action $ACTION"
    exit 0
fi

# only run if from 21.12 release
if [ "${FROM_RELEASE}" != "${ACCEPTED_FROM}" ]; then
    log "$NAME: omit action for from release $FROM_RELEASE"
    exit 0
fi

# only run if to 22.12 release
if [ "${TO_RELEASE}" != "${ACCEPTED_TO}" ]; then
    log "$NAME: omit action for to release $TO_RELEASE"
    exit 0
fi

KUBE_CMD="kubectl --kubeconfig=/etc/kubernetes/admin.conf"

# kubectl sanity
# if kube is configured correctly this should return 0
$KUBE_CMD get ns
if [ $? -ne 0 ]; then
    # this is a sanity condition, do not try to continue
    log "$NAME: sanity: kubectl command failed; abort app upgrade"
    exit 1
fi

EXISTING_APP_INFO=$(
    system application-show $EXISTING_APP_NAME \
        --column app_version --column status --format yaml
)

if [ $? -ne 0 ]; then
    # it is normal for vault application to be absent
    log "$NAME: $EXISTING_APP_NAME is not uploaded; exiting"
    exit 0
fi

EXISTING_APP_VERSION=$(
    echo ${EXISTING_APP_INFO} \
    | sed 's/.*app_version:[[:space:]]\(\S*\).*/\1/'
)
EXISTING_APP_STATUS=$(
    echo ${EXISTING_APP_INFO} \
    | sed 's/.*status:[[:space:]]\(\S*\).*/\1/'
)
ORIGINAL_APP_STATUS=$EXISTING_APP_STATUS

# vault has cert-manager.io resources that are not compatible
# between 21.12 and 22.12.  vault will work normally when those
# resources are deleteed - albiet after recreating the CA and server
# certificates
JPATH='{range .items[*]}{.metadata.name}{" "}{.metadata.ownerReferences[?(@.name=="vault-server-tls")].name}{"\n"}{end}'

function vault_specific_handling {
    $KUBE_CMD delete certificate --ignore-not-found=true --wait=true \
        -n vault vault-server-tls
    $KUBE_CMD delete issuer --ignore-not-found=true --wait=true \
        -n vault ca-issuer
    $KUBE_CMD delete secret --ignore-not-found=true --wait=true \
        -n vault vault-server-tls

    CERT_REQ="$(
        $KUBE_CMD get certificaterequests --ignore-not-found=true \
            -n vault \
            -o jsonpath="$JPATH" \
        | grep " vault-server-tls$" \
        | gawk '{print $1}'
    )"
    if [ -n "$CERT_REQ" ]; then
        $KUBE_CMD delete certificaterequests --wait=true -n vault $CERT_REQ
    fi
}

# Extract the app name and version from the tarball name: app_name-version.tgz
UPGRADE_TARBALL="$(
    find $PLATFORM_APPLICATION_PATH -name "${EXISTING_APP_NAME}*.tgz"
)"
filecount="$( echo "$UPGRADE_TARBALL" | wc -w )"
if [ -z "$UPGRADE_TARBALL" -o "$filecount" -ne 1 ]; then
    # this is a sanity condition, unexpected, do not try to continue
    log "$NAME: ${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}," \
        "upgrade tarball not found (${filecount}).  Exiting for manual" \
        "intervention..."
    exit 1
fi

re='^('${EXISTING_APP_NAME}')-([0-9]+\.[0-9]+-[0-9]+).tgz'
[[ "$(basename $UPGRADE_TARBALL)" =~ $re ]]
UPGRADE_APP_NAME=${BASH_REMATCH[1]}
UPGRADE_APP_VERSION=${BASH_REMATCH[2]}

# Accept the application in the following states
ACCEPTED_STATES="${STATE_APPLIED} ${STATE_UPLOADED}"
if [[ " $ACCEPTED_STATES " != *" $EXISTING_APP_STATUS "* ]]; then
    # This is probably a platform health issue; how does this condition
    # occur?  Do not try to continue
    log "$NAME: ${UPGRADE_APP_NAME}, version ${EXISTING_APP_VERSION}," \
        "in bad state ${EXISTING_APP_STATUS}. Exiting for manual" \
        "intervention..."
    exit 1
fi

log "$NAME: $EXISTING_APP_NAME, version $EXISTING_APP_VERSION," \
    "is currently in the state: $EXISTING_APP_STATUS"

# only upgrade the application if the versions dont match
# in case the upgrade activate failed due to other reasons, and this
# is not the first time this script is run
if [ "x${UPGRADE_APP_VERSION}" == "x${EXISTING_APP_VERSION}" ]; then
    # This could be normal under some circumstances; log and exit softly
    log "$NAME: $UPGRADE_APP_NAME, version $UPGRADE_APP_VERSION, is the same."
    exit 0
fi

# Include app in upgrade in progress file
if ! grep -q "${EXISTING_APP_NAME},${EXISTING_APP_VERSION},${UPGRADE_APP_VERSION}" $UPGRADE_IN_PROGRESS_APPS_FILE; then
    echo "${EXISTING_APP_NAME},${EXISTING_APP_VERSION},${UPGRADE_APP_VERSION}" >> $UPGRADE_IN_PROGRESS_APPS_FILE
fi

if [ "${ORIGINAL_APP_STATUS}" == "${STATE_APPLIED}" ]; then
    # remove old app version
    log "$NAME: Removing ${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}"
    system application-remove -f ${EXISTING_APP_NAME}

    # Wait on the remove, should be somewhat quick
    for tries in $(seq 1 $REMOVE_RESULT_ATTEMPTS); do
        EXISTING_APP_STATUS=$(
            system application-show $EXISTING_APP_NAME \
                --column status --format value
        )
        if [ "${EXISTING_APP_STATUS}" == "${STATE_UPLOADED}" ]; then
            log "$NAME: ${EXISTING_APP_NAME} has been removed."
            break
        fi
        sleep $REMOVE_RESULT_SLEEP
    done

    if [ $tries == $REMOVE_RESULT_ATTEMPTS ]; then
        log "$NAME: ${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}," \
            "was not removed in the allocated time. Exiting for manual" \
            "intervention..."
        exit 1
    fi
fi

# delete old app
log "$NAME: Deleting ${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}"
system application-delete -f ${EXISTING_APP_NAME}

# Wait on the delete, should be quick
for tries in $(seq 1 $DELETE_RESULT_ATTEMPTS); do
    EXISTING_APP_STATUS=$(
        system application-show $EXISTING_APP_NAME \
            --column status --format value
    )
    if [ -z "${EXISTING_APP_STATUS}" ]; then
        log "$NAME: ${EXISTING_APP_NAME} has been deleted."
        break
    fi
    sleep $DELETE_RESULT_SLEEP
done

if [ $tries == $DELETE_RESULT_ATTEMPTS ]; then
    log "$NAME: ${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}," \
        "was not deleted in the allocated time. Exiting for manual" \
        "intervention..."
    exit 1
fi

# delete the cert-manager.io resources
vault_specific_handling

# upload new app version
log "$NAME: Uploading ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION}" \
    "from $UPGRADE_TARBALL"
system application-upload $UPGRADE_TARBALL
# Wait on the upload, should be quick
for tries in $(seq 1 $UPLOAD_RESULT_ATTEMPTS); do
    UPGRADE_APP_STATUS=$(
        system application-show $UPGRADE_APP_NAME \
            --column status --format value
    )
    if [ "${UPGRADE_APP_STATUS}" == "${STATE_UPLOADED}" ]; then
        log "$NAME: ${UPGRADE_APP_NAME} has been uploaded."
        break
    fi
    sleep $UPLOAD_RESULT_SLEEP
done

if [ $tries == $UPLOAD_RESULT_ATTEMPTS ]; then
    log "$NAME: ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION}," \
        "was not uploaded in the allocated time. Exiting for manual" \
        "intervention..."
    exit 1
fi

if [ "${ORIGINAL_APP_STATUS}" == "${STATE_UPLOADED}" ]; then
    log "$NAME: ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION}:" \
        "upload complete"
    exit 0
fi

# apply new app version
log "$NAME: Applying ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION}"
system application-apply ${UPGRADE_APP_NAME}

exit 0
