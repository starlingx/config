#!/bin/bash
#
# Copyright (c) 2020-2025 Wind River Systems, Inc.
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

TIMEOUT=600
KUBE_SYSTEM_NAMESPACE="kube-system"
CERT_MANAGER_NAMESPACE="cert-manager"

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
CRITICAL_APPS='nginx-ingress-controller cert-manager platform-integ-apps'
APPS_NOT_TO_UPDATE=''

TEST_CERT_CM="
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
    creationTimestamp: null
    name: system-local-ca
spec:
    ca:
        secretName: system-local-ca
status: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
    creationTimestamp: null
    name: stx-test-cm
    namespace: cert-manager
spec:
    commonName: stx-test-cm
    issuerRef:
        kind: ClusterIssuer
        name: system-local-ca
    secretName: stx-test-cm
status: {}
"

function log {
    echo "$(date -Iseconds | cut -d'+' -f1): ${NAME}[$$]: INFO: $*" >> "$SOFTWARE_LOG_PATH" 2>&1
}

function get_api_token {
    curl -v -X POST "${1}/auth/tokens" \
    --header 'Content-Type: application/json' \
    --data '{
        "auth": {
            "identity": {
                "methods": [
                    "password"
                ],
                "password": {
                    "user": {
                        "domain": {
                            "name": "Default"
                        },
                        "name": "'${2}'",
                        "password": "'${3}'"
                    }
                }
            },
            "scope": {
                "project": {
                    "domain": {
                        "name": "Default"
                    },
                    "name": "admin"
                }
            }
        }
    }' 2>&1 | sed -n 's/.*[t|T]oken: \(.*\)/\1/p'
}

function verify_apps_are_not_recovering {
    # Scrape app names. Skip header and footer.
    APPS=$(system application-list --nowrap | head -n-1 | tail -n+4 | awk '{print $2}')
    for a in ${APPS}; do
        log "Checking application ${a} current state..."

        # If app is being upgraded then ignore
        if [[ -f $UPGRADE_IN_PROGRESS_APPS_FILE ]] && grep -q $a $UPGRADE_IN_PROGRESS_APPS_FILE; then
            log "${a} is being upgraded."
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

# Check kubernetes health status.
# Exit with status 1 if sysinv-k8s-health command fails
function check_k8s_health {
    local k8s_health
    sysinv-k8s-health --log-file "${SOFTWARE_LOG_PATH}" check
    k8s_health=$?

    if [ $k8s_health -eq 1 ]; then
        exit 1
    fi
}

# As per cert-manager docs, the webhook server can take some time to come up.
# We can ensure the sanity by issuing a certificate as test.
function check_cert_manager {
    log "Issue test certificate to assert cert-manager readyness."
    RETRIES=60

    check_k8s_health
    kubectl delete certificate -n cert-manager stx-test-cm --kubeconfig=/etc/kubernetes/admin.conf --ignore-not-found

    apply_failed=1
    secret_failed=1
    for retry in $( seq 1 ${RETRIES} ); do
        if [ ${apply_failed} -ne 0 ]; then
            log "Apply test certificate CRD..."
            kubectl apply -f <(echo "$TEST_CERT_CM") --kubeconfig=/etc/kubernetes/admin.conf
            if [ $? -ne 0 ]; then
                log "Error applying certificate CRD. Retrying."
                sleep 3
                continue
            fi
            apply_failed=0
        fi
        log "Waiting cert-manager to issue the certificate..."
        sleep 3
        kubectl get secret -n cert-manager stx-test-cm --kubeconfig=/etc/kubernetes/admin.conf
        if [ $? -eq 0 ]; then
            log "cert-manager is ready to issue certificates."
            secret_failed=0
            break
        fi
    done

    check_k8s_health
    kubectl delete certificate -n cert-manager stx-test-cm --kubeconfig=/etc/kubernetes/admin.conf

    if [ ${secret_failed} -ne 0 ]; then
        log "Cert-manager is not ready after the allotted time. Check the pod logs."
        exit 1
    fi
}

function check_pod_readiness {
    # Check the status of nginx-ingress-controller and cert-manager pods

    # Wait for the Nginx Ingress Controller pods to be ready in the background
    check_k8s_health
    log "Waiting for Nginx Ingress Controller Pod Status ..."
    kubectl --kubeconfig=/etc/kubernetes/admin.conf wait --for=condition=ready pod --all=true -n $KUBE_SYSTEM_NAMESPACE -lapp.kubernetes.io/name=ingress-nginx --timeout=${TIMEOUT}s
    RESULT1=$?

    # Wait for the Cert Manager pods to be ready in the background
    check_k8s_health
    log "Waiting for Cert-manager Pod Status ..."
    kubectl --kubeconfig=/etc/kubernetes/admin.conf wait --for=condition=ready pod --all=true -n $CERT_MANAGER_NAMESPACE -lapp=cert-manager --timeout=${TIMEOUT}s
    RESULT2=$?

    # Check the results and provide specific message
    if [ $RESULT1 -eq 0 ] && [ $RESULT2 -eq 0 ]; then
        log "All required pods for Ingress Nginx Controller and Cert Manager are ready."
        check_cert_manager
    elif [ $RESULT1 -ne 0 ] && [ $RESULT2 -eq 0 ]; then
        log "ERROR: Ingress NGINX pods did not become ready within the timeout period."
        exit 1
    elif [ $RESULT1 -eq 0 ] && [ $RESULT2 -ne 0 ]; then
        log "ERROR: Cert Manager pods did not become ready within the timeout period."
        exit 1
    else
        log "ERROR: Both Ingress Nginx Ingress Controller and Cert Manager pods did not become ready within the timeout period."
        exit 1
    fi
}

function update_in_series {
    log "App ${EXISTING_APP_NAME} needs to be updated serially"
    # Wait on the upload, should be quick
    UPDATED=false
    for tries in $(seq 1 $UPDATE_RESULT_ATTEMPTS); do
        UPDATING_APP_INFO=$(system application-show $UPGRADE_APP_NAME --column name --column app_version --column status --format yaml)
        UPDATING_APP_NAME=$(echo ${UPDATING_APP_INFO} | sed 's/.*name:[[:space:]]\(\S*\).*/\1/')
        UPDATING_APP_VERSION=$(echo ${UPDATING_APP_INFO} | sed 's/.*app_version:[[:space:]]\(\S*\).*/\1/')
        UPDATING_APP_STATUS=$(echo ${UPDATING_APP_INFO} | sed 's/.*status:[[:space:]]\(\S*\).*/\1/')

        if [ "${UPDATING_APP_VERSION}" == "${UPGRADE_APP_VERSION}" ] && \
        [ "${UPDATING_APP_STATUS}" == "applied" ]; then
            ALARMS=$(fm alarm-list --nowrap --uuid --query "alarm_id=750.005;entity_type_id=k8s_application;entity_instance_id=${UPGRADE_APP_NAME}" | head -n-1 | tail -n+4 | awk '{print $2}')
            for alarm in ${ALARMS}; do
                log "$NAME: [Warning] A stale 750.005 Application Update In Progress alarm was found for ${UPGRADE_APP_NAME}. Clearing it (UUID: ${alarm})."
                fm alarm-delete $alarm --yes
            done
            log "$NAME: ${UPGRADE_APP_NAME} has been updated to version ${UPGRADE_APP_VERSION} from version ${EXISTING_APP_VERSION}"
            UPDATED=true
            break
        fi
        sleep $UPDATE_RESULT_SLEEP
    done

    if [ $UPDATED == false ] && [ $tries == $UPDATE_RESULT_ATTEMPTS ]; then
        log "$NAME: ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION}, was not updated in the alloted time. Exiting for manual intervention..."
        exit 1
    fi

    if [ $tries != $UPDATE_RESULT_ATTEMPTS ] && [ "${UPDATING_APP_VERSION}" == "${EXISTING_APP_VERSION}" ] ; then
        log "$NAME: ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION}, update failed and was rolled back. Exiting for manual intervention..."
        exit 1
    fi
}

function update_apps {
    PATHS_TO_TARBALLS=$1
    IS_SERIAL_INSTALLATION=$2

    LAST_APP_CHECKED=""
    # Get the list of applications installed in the new release
    for fqpn_app in $PATHS_TO_TARBALLS; do
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

        # Check if the app name is in the list of apps that should not be updated.
        if [[ " $APPS_NOT_TO_UPDATE " == *" $UPGRADE_APP_NAME "* ]]; then
            log "${UPGRADE_APP_NAME} is listed as an app that should not be updated. skipping..."
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
                check_k8s_health
                log "Deleting ${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}"
                system application-delete ${EXISTING_APP_NAME} --yes

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

                check_k8s_health
                log "Uploading ${UPGRADE_APP_NAME}, version ${UPGRADE_APP_VERSION} from $fqpn_app"
                system application-upload $fqpn_app
                ;;

            applied)
                check_k8s_health
                log "Updating ${EXISTING_APP_NAME}, from version ${EXISTING_APP_VERSION} to version ${UPGRADE_APP_VERSION} from $fqpn_app"
                system application-update $fqpn_app

                if [ "$IS_SERIAL_INSTALLATION" == "true" ]; then
                    update_in_series
                fi
                ;;

            upload-failed)
                check_k8s_health
                log "${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}, upload failed: ${EXISTING_APP_STATUS}. Retrying command..."
                retry_command "application-upload" "${EXISTING_APP_NAME}"
                ;;

            apply-failed)
                check_k8s_health
                log "${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}, apply failed: ${EXISTING_APP_STATUS}. Retrying command..."
                retry_command "application-apply" "${EXISTING_APP_NAME}"
                ;;

            remove-failed)
                check_k8s_health
                log "${EXISTING_APP_NAME}, version ${EXISTING_APP_VERSION}, remove failed: ${EXISTING_APP_STATUS}. Retrying command..."
                retry_command "application-remove --yes" "${EXISTING_APP_NAME}"
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
        if [[ ! -f $UPGRADE_IN_PROGRESS_APPS_FILE ]] || ! grep -q "${EXISTING_APP_NAME},${EXISTING_APP_VERSION},${UPGRADE_APP_VERSION}" $UPGRADE_IN_PROGRESS_APPS_FILE; then
            echo "${EXISTING_APP_NAME},${EXISTING_APP_VERSION},${UPGRADE_APP_VERSION}" >> $UPGRADE_IN_PROGRESS_APPS_FILE
            log "Added ${EXISTING_APP_NAME} to upgrade in progress control file."
        fi

        LAST_APP_CHECKED=${UPGRADE_APP_NAME}
    done
}

log "Starting Kubernetes application updates from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"

if [ "$ACTION" == "activate" ]; then
    # remove upgrade in progress file
    [[ -f $UPGRADE_IN_PROGRESS_APPS_FILE ]] && rm -f $UPGRADE_IN_PROGRESS_APPS_FILE

    # move the costly source command in the if branch, so only execute when needed.
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
    check_k8s_health
    K8S_VERSIONS=$(system kube-version-list)
    ACTIVE_K8S_VERSION=$(echo "$K8S_VERSIONS" | grep ' True ' | grep ' active ' | awk -F '|' '{print $2}' | tr -d ' ')

    # Get token
    TOKEN=$(get_api_token "${OS_AUTH_URL}" "${OS_USERNAME}" "${OS_PASSWORD}")

    # Get list of apps that need to be installed serially due to application dependencies.
    REORDER_APPS_ENDPOINT="http://controller:6385/v1/reorder_apps/"
    RESPONSE=$(curl --silent --retry $COMMAND_RETRY_ATTEMPTS --retry-delay $COMMAND_RETRY_SLEEP --write-out "HTTPSTATUS:%{http_code}" -X GET "$REORDER_APPS_ENDPOINT" -H "X-Auth-Token: ${TOKEN}")

    # Capture the HTTP status code
    HTTP_STATUS=$(echo "$RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

    if [[ "$HTTP_STATUS" -ne 200 ]]; then
        log "Unable to get order of apps. Received HTTP status code $HTTP_STATUS."
        exit 1
    fi

    ALL_SYSTEM_SERIAL_APPLICATION=$(echo "$RESPONSE" | sed -e 's/HTTPSTATUS:.*//')

    # Get compatibles tarballs path with current k8s version
    QUERY_COMPATIBLE_APPS_ENDPOINT="http://controller:6385/v1/query_compatible_apps/?k8s_ver=${ACTIVE_K8S_VERSION}&include_path=true"
    RESPONSE=$(curl --silent --retry $COMMAND_RETRY_ATTEMPTS --retry-delay $COMMAND_RETRY_SLEEP --write-out "HTTPSTATUS:%{http_code}" -X GET "$QUERY_COMPATIBLE_APPS_ENDPOINT" -H "X-Auth-Token: ${TOKEN}")

    # Capture the HTTP status code
    HTTP_STATUS=$(echo "$RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

    if [[ "$HTTP_STATUS" -ne 200 ]]; then
        log "Unable to obtain compatible app list. Received HTTP status code $HTTP_STATUS."
        exit 1
    fi

    PATHS_TO_COMPATIBLE_TARBALLS=$(echo "$RESPONSE" | sed -e 's/HTTPSTATUS:.*//')

    # Format values
    ALL_SYSTEM_SERIAL_APPLICATION=$(echo $ALL_SYSTEM_SERIAL_APPLICATION | sed 's/\[//;s/\]//;s/", "/\n/g;s/"//g')
    PATHS_TO_COMPATIBLE_TARBALLS=$(echo $PATHS_TO_COMPATIBLE_TARBALLS | sed 's/\[//;s/\]//;s/", "/\n/g;s/"//g')

    CRITICAL_APPS_PATHS=""

    # From the list of PATHS_TO_COMPATIBLE_TARBALLS, apps that have priority for installation by the platform are separated.
    for app in $CRITICAL_APPS; do
        # Get the first matching path for the app
        matched_path=$(echo "$PATHS_TO_COMPATIBLE_TARBALLS" | grep -m 1 "/$app-")

        # Add the matched path to MATCHED_PATHS if found
        if [ -n "$matched_path" ]; then
            CRITICAL_APPS_PATHS+="$matched_path "
            # Remove the matched path from PATHS_TO_COMPATIBLE_TARBALLS
            PATHS_TO_COMPATIBLE_TARBALLS=$(echo "$PATHS_TO_COMPATIBLE_TARBALLS" | grep -v "$matched_path")
        fi
    done

    APPS_IN_SERIAL_PATH=''
    APPS_IN_PARALLEL_PATHS=''

    # Find matches between ALL_SYSTEM_SERIAL_APPLICATION and PATHS_TO_COMPATIBLE_TARBALLS and save
    # to APPS_IN_SERIAL_PATH
    for app in $ALL_SYSTEM_SERIAL_APPLICATION; do
        # Find the corresponding path in PATHS_TO_COMPATIBLE_TARBALLS
        matched_path=$(echo "$PATHS_TO_COMPATIBLE_TARBALLS" | grep -m 1 "/$app-")

        # If a match is found, append it to APPS_IN_SERIAL_PATH
        if [ -n "$matched_path" ]; then
            APPS_IN_SERIAL_PATH="${APPS_IN_SERIAL_PATH}${matched_path} "
        fi
    done

    # Find unmatched paths between ALL_SYSTEM_SERIAL_APPLICATION and PATHS_TO_COMPATIBLE_TARBALLS
    # and save to APPS_IN_PARALLEL_PATHS
    for path in $PATHS_TO_COMPATIBLE_TARBALLS; do
        if ! echo -e "$APPS_IN_SERIAL_PATH" | grep -q "$path"; then
            APPS_IN_PARALLEL_PATHS="${APPS_IN_PARALLEL_PATHS}${path} "
        fi
    done

    update_apps "$CRITICAL_APPS_PATHS" "true"
    check_pod_readiness

    update_apps "$APPS_IN_PARALLEL_PATHS" "false"
    update_apps "$APPS_IN_SERIAL_PATH" "true"

    log "Completed Kubernetes application updates for release $FROM_RELEASE to $TO_RELEASE with action $ACTION"
else
    log "No actions required for from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"
fi


exit 0
