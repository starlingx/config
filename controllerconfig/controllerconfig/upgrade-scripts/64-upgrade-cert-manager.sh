#!/bin/bash
#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#
# This migration script is used for upgrading cert manager during the
# activate stage of a platform upgrade. It will:
# - dump existing certificates and issuers
# - convert the dump from deprecated v1alpha2 and v1alpha3 to v1
# - remove the old armada version of cert manager
# - apply the new fluxcd version of cert manager
#
# A lot of the logic for determining application versions is copied
# from the generic application upgrade script in order to keep things
# consistent.
#
# This script should only be needed in the upgrade from the armada
# version of cert manager to the fluxcd version of cert manager.
# The cert manager version difference between the armada and fluxcd
# tarball is too great, and require additional steps for data migration.

# The migration scripts are passed these parameters:
NAME=$(basename $0)
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

# only run this script during upgrade-activate
if [ "$ACTION" != "activate" ]; then
    exit 0
fi

PLATFORM_APPLICATION_PATH='/usr/local/share/applications/helm'
CONFIG_PERMDIR="/opt/platform/config/${TO_RELEASE}"
PATH=$PATH:/usr/local/sbin

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

EXISTING_APP_NAME='cert-manager'
EXISTING_APP_INFO=$(system application-show $EXISTING_APP_NAME --column app_version --column status --format yaml)
EXISTING_APP_VERSION=$(echo ${EXISTING_APP_INFO} | sed 's/.*app_version:[[:space:]]\(\S*\).*/\1/')
EXISTING_APP_STATUS=$(echo ${EXISTING_APP_INFO} | sed 's/.*status:[[:space:]]\(\S*\).*/\1/')

# Extract the app name and version from the tarball name: app_name-version.tgz
UPGRADE_CERT_MANAGER_TARBALL=$(find $PLATFORM_APPLICATION_PATH -name "cert-manager*")
re='^(.*)-([0-9]+\.[0-9]+-[0-9]+).tgz'
[[ "$(basename $UPGRADE_CERT_MANAGER_TARBALL)" =~ $re ]]
UPGRADE_APP_NAME=${BASH_REMATCH[1]}
UPGRADE_APP_VERSION=${BASH_REMATCH[2]}

# cert manager is a required application
# if it is not in the applied state, something is very wrong
if [ $EXISTING_APP_STATUS != "applied" ]; then
    log "$NAME: ${UPGRADE_APP_NAME}, version ${EXISTING_APP_VERSION}, in bad state ${EXISTING_APP_STATUS}. Exiting for manual intervention..."
    exit 1
fi

# assuming application is in applied state, but log it anyways
log "$NAME: cert-manager, version $EXISTING_APP_VERSION, is currently in the state: $EXISTING_APP_STATUS"

# only upgrade the application if the versions dont match
# in case the upgrade activate failed due to other reasons, and this
# is not the first time this script is run
if [ "x${UPGRADE_APP_VERSION}" != "x${EXISTING_APP_VERSION}" ]; then

    # dump existing cert manager CRDs
    # only dump once, to prevent overwriting existing dumps
    # if the script is run more than once due to other failures
    if [ ! -f "$CONFIG_PERMDIR/.cm_upgrade_dump" ]; then
        log "$NAME: creating cert manager resources backup"
        EXISTING_CM_RESOURCES=$(kubectl --kubeconfig=/etc/kubernetes/admin.conf \
                                get issuer,clusterissuer,certificates,certificaterequests \
                                --all-namespaces 2>&1 > /dev/null)

        if [ "${EXISTING_CM_RESOURCES}" == 'No resources found' ]; then
            log "$NAME: no existing cert manager resources detected."
            touch "$CONFIG_PERMDIR/.cm_upgrade_no_existing_resources"
        else
            kubectl get -o yaml \
                --kubeconfig=/etc/kubernetes/admin.conf \
                --all-namespaces \
                issuer,clusterissuer,certificates,certificaterequests \
                > $CONFIG_PERMDIR/cert-manager-backup.yaml

            if [ $? != 0 ]; then
                log "$NAME: Failed to dump existing cert manager resources. Exiting for manual intervention..."
                exit 1
            fi
        fi

        touch "$CONFIG_PERMDIR/.cm_upgrade_dump"
    fi

    # convert dump using kubectl cert-manager kubernetes plugin
    # .cm_upgrade_no_existing_resources check is to not convert an empty dump
    # the dump can be empty if the system does not have any cert manager resources.
    # this fails the kubectl plugin and the subsequent kubectl apply to restore the backup.
    if [ ! -f "$CONFIG_PERMDIR/.cm_upgrade_convert" ]  && \
       [ ! -f "$CONFIG_PERMDIR/.cm_upgrade_no_existing_resources" ]; then
        log "$NAME: converting cert manager resources backup"
        kubectl cert-manager convert \
            --output-version cert-manager.io/v1 \
            -f $CONFIG_PERMDIR/cert-manager-backup.yaml \
            > $CONFIG_PERMDIR/cert-manager-v1.yaml

        if [ $? != 0 ]; then
            log "$NAME: Failed to convert cert manager resources. Exiting for manual intervention..."
            exit 1
        fi

        touch "$CONFIG_PERMDIR/.cm_upgrade_convert"
    fi

    # remove extra args overrides.
    # we need to do this because our configuration of cert manager deletes secrets tied to
    # cert manager certificates when the certificates are deleted.
    # this means when we delete the certificates as part of data migration, the secrets are deleted.
    # when the certificates are restored, the underlying secrets will be missing.
    # this triggers a refresh on all cert manager certificates, which could mess up
    # trust chains if the certificates are being used for a rootca, like in DC deployments
    log "$NAME: removing extra args overrides from ${EXISTING_APP_NAME}"
    system helm-override-update ${EXISTING_APP_NAME} cert-manager cert-manager --set extraArgs=""

    # apply old cert manager
    log "$NAME: Applying ${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}"
    system application-apply ${EXISTING_APP_NAME}

    # Wait on the apply
    for tries in $(seq 1 $APPLY_RESULT_ATTEMPTS); do
        EXISTING_APP_STATUS=$(system application-show $EXISTING_APP_NAME --column status --format value)
        if [ "${EXISTING_APP_STATUS}" == 'applied' ]; then
            log "$NAME: ${EXISTING_APP_NAME} has been applied."
            break
        fi
        sleep $APPLY_RESULT_SLEEP
    done

    if [ $tries == $APPLY_RESULT_ATTEMPTS ]; then
        log "$NAME: ${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}, was not applied in the allocated time. Exiting for manual intervention..."
        exit 1
    fi

    # remove old cert manager
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


    # delete old cert manager
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


    # upload new cert manager
    log "$NAME: Uploading ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION} from $UPGRADE_CERT_MANAGER_TARBALL"
    system application-upload $UPGRADE_CERT_MANAGER_TARBALL
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


    # apply new cert manager
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

    # apply converted cert manager resources to the new cert manager application
    # -f check is required because the cert manager backup could be empty
    # if the system had no cert manager resources before the upgrade
    if [ ! -f "$CONFIG_PERMDIR/.cm_upgrade_no_existing_resources" ]; then
        log "$NAME: Restoring cert manager resource backup"
        kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f $CONFIG_PERMDIR/cert-manager-v1.yaml

        if [ $? != 0 ]; then
            log "$NAME: Failed to apply cert manager resources on the fluxcd version of cert manager. Exiting for manual intervention..."
            exit 1
        fi
    fi


fi

exit 0
