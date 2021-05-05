#!/bin/bash
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Utility for patching Kubernetes Persistent Volumes during
# AIO-SX to AIO-DX migration.
#
# This is required because Ceph-mon IP address changes
# from controller-0 to floating controller IP. Therefore,
# existing PV claims backed by cephfs or RBD will fail to
# mount due to previous monitor being inaccessible.

# Logging info.
NAME=$(basename $0)

# This will log to /var/log/platform.log
# and stdout
function log {
    logger -p local1.info "$NAME: $1"
    echo "$1"
}

function help {
    echo "Utility for patching Kubernetes Persistent Volumes during AIO-SX to AIO-DX migration"
    echo
    echo "Syntax: $NAME [-h] CONTROLLER_0_MGMT_IP FLOATING_CONTROLLER_MGMT_IP"
    echo "options:"
    echo "h     Prints this Help."
    echo
}

while getopts ":h" option; do
    case $option in
        h)
            help
            exit;;
        \?)
            log "Error: Invalid option"
            exit;;
    esac
done

if [ $# -ne 2 ]; then
    log "Error: Wrong number of arguments"
    log "Run $NAME -h for help"
    exit 1
fi

# read input arguments
CONTROLLER_0_IP=$1
CONTROLLER_FLOATING_IP=$2

function check_pv_need_migration {
    local mon
    mon=$(kubectl --kubeconfig=/etc/kubernetes/admin.conf get PersistentVolume $1 -o jsonpath='{.spec.*.monitors}')
    echo $mon | grep -q $CONTROLLER_0_IP
}

ITER=0
MAX_ITER=5
while [[ $ITER -le $MAX_ITER ]]; do
    kubectl --kubeconfig=/etc/kubernetes/admin.conf get StorageClass --all-namespaces > /dev/null
    if [ $? -ne 0 ]; then
        log "kubernetes api is not available. Retry ${ITER} of ${MAX_ITER}"
        ITER=$((ITER + 1))
        sleep 30
    else
        break
    fi
done

if [[ $ITER -gt $MAX_ITER ]]; then
    log "kubernetes api is not available. Exiting with failure"
    exit 1
fi

STORAGE_CLASSES=$(kubectl --kubeconfig=/etc/kubernetes/admin.conf get StorageClass --all-namespaces | \
    grep -E "ceph.com/cephfs|ceph.com/rbd" | awk '{print $1}')
EXISTING_PVCS=$(kubectl --kubeconfig=/etc/kubernetes/admin.conf get PersistentVolume --all-namespaces --no-headers | awk '{print $1}')

for PVC in $EXISTING_PVCS; do
    PVC_SC=$(kubectl --kubeconfig=/etc/kubernetes/admin.conf get PersistentVolume $PVC -o json | \
            grep -Eo '"storageClassName"[^,]*' | awk '{print $2}' | sed 's/"//g')

    for SC in ${STORAGE_CLASSES}
    do
        if [ "$SC" == "$PVC_SC" ]; then
            # Loops over existing Persistent Volumes and replace it changing the CEPH monitor ip address
            # This is required because updating the monitor ip is not allowed by kubernetes and therefore we need
            # to re-create it. The replace command will block due to the pv-protection finalizer waiting for the bounded PVC
            # to be removed but we want to replace the PV without removing the bounded PVC. Therefore, we run the replace command
            # in the background and run a patch removing the pv-protection finalizer so that replace command completes.
            check_pv_need_migration $PVC
            if [ $? -ne 0 ]; then
                log "skipping PersistentVolume/${PVC} - already patched"
                continue
            fi

            log "Started patching PersistentVolume/${PVC}"
            kubectl --kubeconfig=/etc/kubernetes/admin.conf get PersistentVolume $PVC -o yaml | sed "s/$CONTROLLER_0_IP/$CONTROLLER_FLOATING_IP/g" | \
                kubectl --kubeconfig=/etc/kubernetes/admin.conf replace --cascade=false --force -f - >/dev/null &
            sleep 1
            TIMEOUT=4
            DELAY=0
            while [[ $DELAY -lt $TIMEOUT ]]; do
                timestamp=$(kubectl --kubeconfig=/etc/kubernetes/admin.conf get PersistentVolume $PVC -o jsonpath='{.metadata.deletionTimestamp}')
                if [ ! -z "${timestamp}" ]; then
                    break
                else
                    sleep 1
                    DELAY=$((DELAY + 1))
                fi
            done

            if [[ $DELAY -lt $TIMEOUT ]]; then
                kubectl --kubeconfig=/etc/kubernetes/admin.conf patch PersistentVolume ${PVC} -p '{"metadata":{"finalizers":null}}' --type=merge
                wait
                log "PersistentVolume/${PVC} replaced"
            else
                log "Timed out waiting to patch PersistentVolume/${PVC}"
                exit 1
            fi
        fi
    done
done

exit 0
