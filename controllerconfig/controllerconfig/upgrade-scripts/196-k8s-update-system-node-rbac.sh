#!/bin/bash
#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# The script updates system:node clusterrole with namespaces with get and list
# as verbs. It also adds all compute hosts' names as subjects to the
# system:node clusterrolebinding.
# To reflect this update, the script restarts kubelets on all compute hosts.
#
# This change allows kubelet to communicate
# with kube-apiserver to get labels of all namespace objects which is required
# for platform pods identification.
#

# shellcheck disable=SC2076,SC2086,SC2089,SC2090

# The migration scripts are passed these parameters:
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3
KUBECTL_CMD="kubectl --kubeconfig=/etc/kubernetes/admin.conf"
SOFTWARE_LOG_PATH="/var/log/software.log"
rbac_updated="1"

# Standard logging method copied from 02 script
function log {
    echo "$(date -Iseconds | cut -d'+' -f1): ${NAME}[$$]: INFO: $*" \
        >> "${SOFTWARE_LOG_PATH}" 2>&1
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

get_compute_hosts() {

    k8s_nodes=$(${KUBECTL_CMD} get nodes --no-headers \
                -o custom-columns=NAME:.metadata.name 2>&1)

    RC=$?
    if [[ "${RC}" != "0" ]]; then
        log "Failed to get compute hosts. Error: ${k8s_nodes}"
        exit ${RC}
    fi

    echo "${k8s_nodes}"

}

system_node_clusterrolebinding_add_hosts() {

    compute_hostnames=$(get_compute_hosts)

    readarray -t compute_hosts_arr <<< "${compute_hostnames}"

    value="["

    for host in "${compute_hosts_arr[@]}"; do
        value+="{\"apiGroup\":\"rbac.authorization.k8s.io\",\"kind\":\"User\",\"name\":\"system:node:${host}\"},"
    done

    # Trim trailing ',' and add closing ']'
    value="$(echo "${value}]" | sed 's/\(.*\),/\1/')"

    cmd_output=$(${KUBECTL_CMD} patch clusterrolebinding system:node \
        --type='json' \
        --patch="[{\"op\":\"add\",\"path\":\"/subjects\",\"value\":${value}}]" \
        2>&1)

    RC=$?
    if [[ "${RC}" == "0" ]]; then
        if [[ "${cmd_output}" =~ '(no change)' ]]; then
            log "system:node clusterrolebinding was already updated with compute hostnames. Unchanged."
        else
            log "system:node clusterrolebinding updated successfully with compute hostnames."
            rbac_updated="0"
        fi
    else
        log "Failed to add compute hosts to clusterrolebinding. Error: ${cmd_output}"
        exit ${RC}
    fi

}

system_node_clusterrolebinding_remove_hosts() {

    subjects=$(${KUBECTL_CMD} get clusterrolebinding system:node \
                -o jsonpath='{.subjects}')

    if [[ -n "${subjects}" ]] && [[ "${subjects}" != " " ]]; then

        remove_hosts_cmd="$(${KUBECTL_CMD} patch clusterrolebinding system:node \
        --type='json' --patch='[{"op":"remove","path":"/subjects"}]' 2>&1)"

        RC=$?
        if [[ "${RC}" == "0" ]]; then
            log "Compute hostnames removed from system:node clusterrolebinding."
        else
            log "Failed to remove compute hosts from the system:node clusterrolebinding. Error: ${remove_hosts_cmd}"
            exit ${RC}
        fi

    else
        log "Compute hostnames have already been removed from system:node clusterrolebinding. Nothing to do ..."
    fi

}

system_node_clusterrole_add_namespaces() {

    all_resource_verbs=$(${KUBECTL_CMD} get clusterrole system:node \
                -o jsonpath='{range .rules[*]}{.resources[0]}{.verbs}{","}' \
                2>&1)

    if [[ "${all_resource_verbs}" =~ 'namespaces["get","list"]' ]]; then
        log "system:node clusterrole is already updated with namespaces. No update required."
        return
    fi

    add_ns_cmd=$(${KUBECTL_CMD} patch clusterrole system:node --type='json' \
    --patch='[{"op":"add","path":"/rules/0","value":{"apiGroups":[""],"resources":["namespaces"],"verbs":["get","list"]}}]' \
    2>&1)

    RC=$?
    if [[ "${RC}" == "0" ]]; then
        log "system:node clusterrole updated successfully with namespaces."
        rbac_updated="0"
    else
        log "Failed to add namespaces to the system:node clusterrole: Error: ${add_ns_cmd}"
        exit ${RC}
    fi

}

system_node_clusterrole_remove_namespaces() {

    all_resource_verbs=$(${KUBECTL_CMD} get clusterrole system:node \
                -o jsonpath='{range .rules[*]}{.resources[0]}{.verbs}{","}')

    # In case activate-rollback had to run more than once, we should first
    # check that we are removing the intended rule.
    if [[ "${all_resource_verbs}" =~ 'namespaces["get","list"]' ]]; then

        remove_ns_cmd="$(${KUBECTL_CMD} patch clusterrole system:node \
        --type='json' --patch='[{"op":"remove","path":"/rules/0"}]' 2>&1)"

        RC=$?
        if [[ "${RC}" == "0" ]]; then
            log "Namespaces removed from system:node clusterrole."
        else
            log "Failed to remove namespaces from the system:node clusterrole. Error: ${remove_ns_cmd}"
            exit ${RC}
        fi

    else
        log "Namespaces have already been removed from system:node clusterrole. Nothing to do ..."
    fi

}

log "Starting Kubernetes system:node RBAC update from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"

if [[ "${ACTION}" == "activate" ]] && [[ "${TO_RELEASE}" == "24.09" ]]; then

    check_k8s_health

    system_node_clusterrolebinding_add_hosts

    system_node_clusterrole_add_namespaces

    # Restart kubelet on all Kubernetes nodes if RBAC has been updated
    if [[ "${rbac_updated}" == "0" ]]; then

        system kube-config-kubelet

        # Wait for Kubernetes to be ready.
        check_k8s_health

        RC=$?
        if [[ "${RC}" == "0" ]]; then
            log "Kubernetes system:node RBAC updated successfully from $FROM_RELEASE to $TO_RELEASE with action $ACTION"
        else
            log "Failed to update kubernetes system:node RBAC. Error code: ${RC}"
            exit ${RC}
        fi

    fi

elif [[ "${ACTION}" == "activate-rollback" ]] && [[ "${TO_RELEASE}" == "24.09" ]]; then

    check_k8s_health

    system_node_clusterrolebinding_remove_hosts

    system_node_clusterrole_remove_namespaces

    # Wait for Kubernetes to be ready.
    check_k8s_health

    log "Kubernetes system:node RBAC rollback successful from $FROM_RELEASE to $TO_RELEASE with action $ACTION"

else
    log "No actions required for from release $FROM_RELEASE to $TO_RELEASE with action $ACTION"
fi

exit 0
