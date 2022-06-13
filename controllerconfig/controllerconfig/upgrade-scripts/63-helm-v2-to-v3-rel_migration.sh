#!/bin/bash
# vim: tabstop=4 shiftwidth=4 expandtab
#
# Copyright (c) 2020-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# This migration script is used for migrating helmV2 applications helmrelease to
# helmV3, therefore this enables armada apps to be upgrade to FluxCD apps in a
# platform upgrade: It will:
# - Install helm-2to3 plugin
# - Move helm2 config to helm3
# - Run migration script for each release

set -ef

NAME=$(basename $0)

# The migration scripts are passed these parameters:
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

PATH=$PATH:/usr/local/sbin:/usr/bin

# This will log to /var/log/platform.log
function log {
    logger -p local1.info $1
}

function install_helm_2to3 {
    log "$NAME: Installing helm 2to3 plugin"
    if ! helm plugin list | grep 2to3; then
        export HELM_LINTER_PLUGIN_NO_INSTALL_HOOK=true
        helm plugin install /usr/local/share/helm/plugins/2to3
    else
        log "$NAME: helm 2to3 already present"
    fi
}

function get_helmv2_config {
    log "$NAME: Retreiving helm config from Armada's tiller container."
    JSONPATH='{range .items[*]}{"\n"}{@.metadata.name}:{@.metadata.deletionTimestamp}{range @.status.conditions[*]}{":"}{@.type}={@.status}{end}{end}'
    ARMADA_PODS=( $(kubectl get pods -n armada \
                    --kubeconfig=/etc/kubernetes/admin.conf \
                    --selector=application=armada,component=api \
                    --field-selector status.phase=Running \
                    --output=jsonpath="${JSONPATH}") )
    if [ ${#ARMADA_PODS[@]} -eq 0 ]; then
        log "$NAME: ERROR - Could not find armada pod."
        exit 1
    fi

    # Get first available Running and Ready armada pod, with tiller container
    POD=""
    for LINE in "${ARMADA_PODS[@]}"; do
        # match only Ready pods with nil deletionTimestamp
        if [[ $LINE =~ ::.*Ready=True ]]; then
            # extract pod name, it is first element delimited by :
            A=$( cut -d ':' -f 1 - <<< "${LINE}" )
            P=${A[0]}
        else
            continue
        fi
        kubectl  --kubeconfig=/etc/kubernetes/admin.conf \
            cp armada/${P}:tmp/.helm "$HOME"/.helm -c tiller
        RC=$?
        if [ ${RC} -eq 0 ]; then
            log "$NAME: helmv2 config copied to /home/sysadmin/.helm"
            break
        else
            log "$NAME: ERROR - failed to copy helm config from helmv2 (tiller) to host. (RETURNED: $RC)"
            exit 1
        fi
    done

    yes | helm 2to3 move config
    RC=$?
    if [ ${RC} -eq 0 ]; then
        log "$NAME: helmV2 release info and config moved to helmv3"
    else
        log "$NAME: ERROR - failed to migrate release info to helmv3. (RETURNED: $RC)"
        exit 1
    fi
}

function migrate_apps {
    log "$NAME: Migrating helm releases"
    APPS=$(KUBECONFIG=/etc/kubernetes/admin.conf helmv2-cli -- helm list -a | tail -n+2 | awk '{print $1}')
    for app in ${APPS}; do
            case $app in
                ic-nginx-ingress | cm-cert-manager | cm-cert-manager-psp-rolebinding)
                    log "$NAME: unsuported migration for $app"
                    ;;
                *)
                    log "$NAME: migrating $app helmrelease"
                    /usr/bin/migrate_helm_release.py $app
                    ;;
            esac
    done
}

if [ "$ACTION" == "activate" ]; then
    log "$NAME: Starting Helm release migration from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"
    install_helm_2to3
    get_helmv2_config
    migrate_apps
    helm plugin uninstall 2to3
fi

exit 0