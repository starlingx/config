#!/bin/bash
#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#
# This migration script is used for upgrading portieris during the
# activate stage of a platform upgrade if portieris is applied. It will:
# - dump existing image policy and cluster image policy
# - convert the dump to the new format accepted by the new version of
#   portieris
# - remove the old armada version of portieris
# - apply the new fluxcd version of portieris
#
# A lot of the logic for determining application versions is copied
# from the generic application upgrade script in order to keep things
# consistent.
#
# This script should only be needed in the upgrade from the armada
# version of portieris to the fluxcd version of portieris.
# The portieris version difference between the armada and fluxcd
# tarball is too great, and require additional steps for data migration.


# The migration scripts are passed these parameters:
NAME=$(basename $0)
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

# This will log to /var/log/platform.log
function log {
    logger -p local1.info $1
}

# only run this script during upgrade-activate and upgrade-start
if [[ "$ACTION" != "activate" &&  "$ACTION" != "start" ]]; then
    exit 0
fi

# only run from 21.12 to 22.12
if [[ "$TO_RELEASE" != "22.12" || "$FROM_RELEASE" != "21.12" ]]; then
    log "skipping Portieris upgrade script. unsupported release"
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

EXISTING_APP_NAME='portieris'
EXISTING_APP_INFO=$(system application-show $EXISTING_APP_NAME --column app_version --column status --format yaml)
EXISTING_APP_VERSION=$(echo ${EXISTING_APP_INFO} | sed 's/.*app_version:[[:space:]]\(\S*\).*/\1/')
EXISTING_APP_STATUS=$(echo ${EXISTING_APP_INFO} | sed 's/.*status:[[:space:]]\(\S*\).*/\1/')

# Extract the app name and version from the tarball name: app_name-version.tgz
UPGRADE_PORTIERIS_TARBALL=$(find $PLATFORM_APPLICATION_PATH -name "portieris*")
re='^(.*)-([0-9]+\.[0-9]+-[0-9]+).tgz'
[[ "$(basename $UPGRADE_PORTIERIS_TARBALL)" =~ $re ]]
UPGRADE_APP_NAME=${BASH_REMATCH[1]}
UPGRADE_APP_VERSION=${BASH_REMATCH[2]}

# portieris is an optional application
# only do something if it is in "applied" or "uploaded" state
if [[ $EXISTING_APP_STATUS != "applied" && $EXISTING_APP_STATUS != "uploaded" ]]; then
    log "$NAME: ${UPGRADE_APP_NAME}, version ${EXISTING_APP_VERSION}, not in upgradeable state: ${EXISTING_APP_STATUS}, skipping"
    exit 0
fi

log "$NAME: portieris, version $EXISTING_APP_VERSION, is currently in the state: $EXISTING_APP_STATUS"


# upgrade start
# we need to delete the webhook if portieris is applied.
# leaving the webhook creates issues when the portieris pod is down,
# which prevents ALL pods from coming back up, including base kubernetes pods
if [[ "$ACTION" == "start" ]]; then
    if [[ $EXISTING_APP_STATUS == "applied" ]]; then
        EXISTING_WEBHOOK=$(kubectl --kubeconfig=/etc/kubernetes/admin.conf \
                                                get MutatingWebhookConfiguration image-admission-config \
                                                2>&1 > /dev/null)

        if [[ "${EXISTING_WEBHOOK}" != *'not found' ]]; then
            log "$NAME: deleting portieris webhook"
            kubectl --kubeconfig=/etc/kubernetes/admin.conf delete MutatingWebhookConfiguration image-admission-config

            if [ $? != 0 ]; then
                log "$NAME: Failed to delete portieris webhook. Exiting for manual intervention..."
                exit 1
            fi

        fi
    fi
    exit 0
fi


# the rest of this script is for "upgrade-activate"


# only upgrade the application if the versions dont match
# in case the upgrade activate failed due to other reasons, and this
# is not the first time this script is run
if [ "x${UPGRADE_APP_VERSION}" != "x${EXISTING_APP_VERSION}" ]; then

    # portieris is applied
    # do the data migration and upgrade through remove and apply of new version
    if [[ $EXISTING_APP_STATUS == "applied" ]]; then

        # export overrides
        # the portieris overrides will likely not be compatible since the charts changed quite a bit
        # the portieris-certs charts have not changed, and should be transferred to the new version
        # the overrides only support a single value: caCert
        # this means it should be fine to get the output from "system helm-override-show" instead of the database
        log "$NAME: Exporting portieris-certs overrides"
        OVERRIDE_OUTPUT=$(system helm-override-show portieris portieris-certs portieris | grep user_overrides)
        OVERRIDES=${OVERRIDE_OUTPUT%?}
        OVERRIDES=$(echo $OVERRIDES | cut -d " "  -f 4-)

        if [[ "$OVERRIDES" != "None" ]]; then
            echo $OVERRIDES > $CONFIG_PERMDIR/portieris-certs-overrides.yaml
        fi


        # dump existing image policies and cluster image policies.
        # only dump once, to prevent overwriting existing dumps
        # if the script is run more than once due to other failures.
        # do not dump default (cluster) image policies, as that would restore
        # them onto the new portieris application, which comes with its own defaults.
        if [ ! -f "$CONFIG_PERMDIR/.portieris_upgrade_dump" ]; then
            log "$NAME: creating portieris resources backup"
            EXISTING_PORTIERIS_RESOURCES=$(kubectl --kubeconfig=/etc/kubernetes/admin.conf \
                                    get imagepolicy,clusterimagepolicy \
                                    --all-namespaces \
                                    --field-selector metadata.name!=default 2>&1 > /dev/null)

            if [ "${EXISTING_PORTIERIS_RESOURCES}" == 'No resources found' ]; then
                log "$NAME: no existing portieris resources detected."
                touch "$CONFIG_PERMDIR/.portieris_upgrade_no_existing_resources"
            else
                kubectl get -o yaml \
                    --kubeconfig=/etc/kubernetes/admin.conf \
                    --all-namespaces \
                    --field-selector metadata.name!=default \
                    imagepolicy,clusterimagepolicy \
                    > $CONFIG_PERMDIR/portieris-backup.yaml

                if [ $? != 0 ]; then
                    log "$NAME: Failed to dump existing portieris resources. Exiting for manual intervention..."
                    exit 1
                fi
            fi

            touch "$CONFIG_PERMDIR/.portieris_upgrade_dump"
        fi

        # convert dump of portieris resources
        # upstream developer confirmed its just a name change on the apiversion
        # .portieris_upgrade_no_existing_resources check is to not convert an empty dump
        # the dump can be empty if the system does not have any portieris resources.
        # this fails the subsequent kubectl apply to restore the backup.
        if [ ! -f "$CONFIG_PERMDIR/.portieris_upgrade_convert" ]  && \
           [ ! -f "$CONFIG_PERMDIR/.portieris_upgrade_no_existing_resources" ]; then
            log "$NAME: converting portieris resources backup"

            sed 's;apiVersion: securityenforcement.admission.cloud.ibm.com/v1beta1;apiVersion: portieris.cloud.ibm.com/v1;' \
                $CONFIG_PERMDIR/portieris-backup.yaml > \
                $CONFIG_PERMDIR/portieris-converted.yaml

            if [ $? != 0 ]; then
                log "$NAME: Failed to convert portieris resources. Exiting for manual intervention..."
                exit 1
            fi

            # delete some fields from the export that prevents applying the export
            sed -i '/creationTimestamp:/d' $CONFIG_PERMDIR/portieris-converted.yaml
            if [ $? != 0 ]; then
                log "$NAME: Failed to delete creationTimestamp in portieris export. Exiting for manual intervention..."
                exit 1
            fi

            sed -i '/resourceVersion:/d' $CONFIG_PERMDIR/portieris-converted.yaml
            if [ $? != 0 ]; then
                log "$NAME: Failed to delete resourceVersion in portieris export. Exiting for manual intervention..."
                exit 1
            fi

            sed -i '/selfLink:/d' $CONFIG_PERMDIR/portieris-converted.yaml
            if [ $? != 0 ]; then
                log "$NAME: Failed to delete selfLink in portieris export. Exiting for manual intervention..."
                exit 1
            fi

            sed -i '/uid:/d' $CONFIG_PERMDIR/portieris-converted.yaml
            if [ $? != 0 ]; then
                log "$NAME: Failed to delete uid in portieris export. Exiting for manual intervention..."
                exit 1
            fi

            touch "$CONFIG_PERMDIR/.portieris_upgrade_convert"
        fi

        # remove old portieris
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


        # cleanup old portieris objects
        # the old portieris does not remove cleanly. we need to delete some leftovers
        # in order to get the new portieris to apply properly
        kubectl --kubeconfig=/etc/kubernetes/admin.conf delete namespace portieris
        kubectl --kubeconfig=/etc/kubernetes/admin.conf delete clusterrolebinding admission-portieris-webhook
        kubectl --kubeconfig=/etc/kubernetes/admin.conf delete clusterrole portieris

        # delete old portieris
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


        # upload new portieris
        log "$NAME: Uploading ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION} from $UPGRADE_PORTIERIS_TARBALL"
        system application-upload $UPGRADE_PORTIERIS_TARBALL
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


        # apply overrides
        if [ -f "$CONFIG_PERMDIR/portieris-certs-overrides.yaml" ]; then
            log "$NAME: restoring portieris-certs overrides."
            system helm-override-update portieris portieris-certs portieris --values $CONFIG_PERMDIR/portieris-certs-overrides.yaml

            if [ $? != 0 ]; then
                log "$NAME: Failed to apply portieris overrides. Exiting for manual intervention..."
                exit 1
            fi

        fi

        # download new portieris image, since it comes from a new registry
        # which is not configured in the previous release
        log "$NAME: adding portieris image to local registry"
        IMAGE="portieris/portieris:v0.13.1"
        system registry-image-tags icr.io/portieris/portieris| grep 'v0\.13\.1'
        if [ $? -eq 0 ]; then
            log "$NAME: image ${IMAGE} already exists, nothing needs to be done."
        else
            DOCKER_REGISTRY_UUID=$( system service-parameter-list --service docker --section docker-registry | grep " url " | awk -F '|' '{print $2}'| xargs );
            DOCKER_REGISTRY_VALUE=$( system service-parameter-show $DOCKER_REGISTRY_UUID | grep " value " | awk -F '|' '{print $3}'| xargs );
            ICR_REGISTRY=$(echo $DOCKER_REGISTRY_VALUE | sed 's;/docker;/icr;');

            # check if the system is configured to pull from an authenticated registry
            REGISTRY_IS_AUTHED=0
            system service-parameter-list --service docker --section docker-registry | grep auth-secret
            if [ $? -eq 0 ]; then
                REGISTRY_IS_AUTHED=1
                log "$NAME: logging in to docker registry using credentials stored in barbican"
                BARBICAN_SECRET_UUID=$(system service-parameter-list --service docker --section docker-registry | grep auth-secret | awk -F '|' '{print $6}' | xargs);
                BARBICAN_SECRET=$( openstack secret get $BARBICAN_SECRET_UUID -p -f value );
                DOCKER_REGISTRY_CREDS=$(echo $BARBICAN_SECRET | sed 's;username:;-u ;' | sed 's;password:;-p ;')
                docker login $DOCKER_REGISTRY_VALUE $DOCKER_REGISTRY_CREDS
            fi
            docker pull ${ICR_REGISTRY}/${IMAGE};
            docker tag ${ICR_REGISTRY}/${IMAGE} registry.local:9001/icr.io/${IMAGE}
            echo ${OS_PASSWORD} | docker login -u ${OS_USERNAME} --password-stdin registry.local:9001
            docker push registry.local:9001/icr.io/${IMAGE}

            if [ $REGISTRY_IS_AUTHED -eq 1 ]; then
                docker logout $DOCKER_REGISTRY_VALUE
            fi

            # double check the image tag
            system registry-image-tags icr.io/portieris/portieris | grep 'v0\.13\.1'
            if [ $? -ne 0 ]; then
                log "$NAME: $IMAGE not tagged correctly, exiting for manual intervention"
                exit 1
            else
                log "$NAME: done."
            fi
        fi

        # apply new portieris
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

        # apply converted portieris resources to the new portieris application
        # -f check is required because the portieris backup could be empty
        # if the system had no portieris resources before the upgrade
        if [ ! -f "$CONFIG_PERMDIR/.portieris_upgrade_no_existing_resources" ]; then
            log "$NAME: Restoring portieris resource backup"
            kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f $CONFIG_PERMDIR/portieris-converted.yaml

            if [ $? != 0 ]; then
                log "$NAME: Failed to apply portieris resources on the fluxcd version of portieris. Exiting for manual intervention..."
                exit 1
            fi
        fi

    fi

    # portieris is uploaded
    # delete the old and upload the new
    if [[ $EXISTING_APP_STATUS == "uploaded" ]]; then

        # delete old portieris
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


        # upload new portieris
        log "$NAME: Uploading ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION} from $UPGRADE_PORTIERIS_TARBALL"
        system application-upload $UPGRADE_PORTIERIS_TARBALL
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

    fi

fi

exit 0
