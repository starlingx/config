#!/bin/bash
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

#
# chkconfig: 2345 80 80
#

### BEGIN INIT INFO
# Provides:          affine-tasks
# Required-Start:
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: reaffine tasks on AIO
# Description:       This script will dynamically reaffine tasks
#   and k8s-infra cgroup cpuset on AIO nodes only. This accomodates
#   CPU intensive phases of work. Tasks are initially allowed to float
#   across all cores. Once system is at steady-state, this will ensure
#   that K8S pods are constrained to platform cores and do not run on
#   cores with VMs/containers.
### END INIT INFO
#
# Background:
# There is significant parallel CPU intensive activity:
# - during stx-application apply before critical openstack pods are running,
#   e.g., to download docker images, and start all pods.
# - during init and pod recovery after reboot or DOR.
#
# This enables use of all cpus during CPU intensive phase, otherwise the
# startup processing time is considerably longer and we easily hit timeout.
#
# This script waits forever for sufficient platform readiness criteria
# (e.g., system critical pods are recovered, nova-compute is running,
# cinder-volume is running, openstack pods are running), and we have waited
# a short stabilization period before reaffining to the platform cpus.
#
# NOTE: child cgroup cpuset and nodeset must be a subset of the parent
# cgroup's attributes.  This requires traversing the tree hierachy in
# specific order when dynamically modifying these attributes.
#
################################################################################
# Define minimal path
PATH=/bin:/usr/bin:/usr/sbin:/usr/local/bin

CPUMAP_FUNCTIONS=${CPUMAP_FUNCTIONS:-"/etc/init.d/cpumap_functions.sh"}
[[ -e ${CPUMAP_FUNCTIONS} ]] && source ${CPUMAP_FUNCTIONS}

# Bring in platform definitions
. /etc/platform/platform.conf

# Environment for kubectl
export KUBECONFIG=/etc/kubernetes/admin.conf

# Global parameters
CGDIR_K8S=/sys/fs/cgroup/cpuset/k8s-infra
INIT_INTERVAL_SECONDS=10
CHECK_INTERVAL_SECONDS=30
PRINT_INTERVAL_SECONDS=300
STABILIZATION_SECONDS=150

# Define pidfile
LNAME=$(readlink -n -f $0)
NAME=$(basename $LNAME)
PIDFILE=/var/run/${NAME}.pid

# Define number of logical cpus
LOGICAL_CPUS=$(getconf _NPROCESSORS_ONLN)

# Define the memory nodeset and cpuset that span all online cpus and nodes
ONLINE_NODES=$(/bin/cat /sys/devices/system/node/online)
ONLINE_CPUS=$(/bin/cat /sys/devices/system/cpu/online)
ONLINE_MASK=$(cpulist_to_cpumap ${ONLINE_CPUS} ${LOGICAL_CPUS} | \
                awk '{print tolower($0)}')

ISOL_CPUS=$(/bin/cat /sys/devices/system/cpu/isolated)
if [ ! -z "${ISOL_CPUS}" ]; then
    ISOL_CPUMAP=$(cpulist_to_cpumap ${ISOL_CPUS} ${LOGICAL_CPUS})
    NONISOL_CPUMAP=$(invert_cpumap ${ISOL_CPUMAP} ${LOGICAL_CPUS})
    NONISOL_CPUS=$(cpumap_to_cpulist ${NONISOL_CPUMAP} ${LOGICAL_CPUS})
    NONISOL_MASK=$(cpulist_to_cpumap ${NONISOL_CPUS} ${LOGICAL_CPUS} | \
                    awk '{print tolower($0)}')
else
    ISOL_CPUMAP='0'
    NONISOL_CPUS=${ONLINE_CPUS}
    NONISOL_MASK=${ONLINE_MASK}
fi

# Define platform memory nodeset and cpuset
PLATFORM_NODES=$(cat /sys/devices/system/node/online)
PLATFORM_CPUS=$(platform_expanded_cpu_list)

# Global variables
NOT_READY_REASON=""
STABLE=0

# Log info message to /var/log/daemon.log
function LOG {
    logger -p daemon.info -t "${NAME}($$): " "$@"
}

# Log error message to /var/log/daemon.log
function ERROR {
    logger -s -p daemon.error -t "${NAME}($$): " "$@"
}

# Update cgroup k8s-infra cpuset and nodeset to span all non-isolated cpus.
function update_cgroup_cpuset_k8s_infra_all {
    # Set all cgroup cpuset and nodeset in tree hierarchy order.
    # This will always work, no matter the previous cpuset state.
    find ${CGDIR_K8S} -type d | \
    while read d; do
        /bin/echo ${ONLINE_NODES} > ${d}/cpuset.mems 2>/dev/null
        /bin/echo ${NONISOL_CPUS} > ${d}/cpuset.cpus 2>/dev/null
    done
    LOG "Update ${CGDIR_K8S}," \
        "ONLINE_NODES=${ONLINE_NODES}, NONISOL_CPUS=${NONISOL_CPUS}"
}

# Update cgroup k8s-infra to span platform cpuset and nodeset.
function update_cgroup_cpuset_k8s_infra_platform {
    # Clear any existing cpuset settings. This ensures that the
    # subsequent shrink to platform cpuset will always work.
    update_cgroup_cpuset_k8s_infra_all

    # Set all cgroup cpuset and nodeset in depth-first order.
    # NOTE: this only works if we are shrinking the cpuset.
    find ${CGDIR_K8S} -depth -type d | \
    while read d; do
        /bin/echo ${PLATFORM_NODES} > ${d}/cpuset.mems 2>/dev/null
        /bin/echo ${PLATFORM_CPUS}  > ${d}/cpuset.cpus 2>/dev/null
    done
    LOG "Update ${CGDIR_K8S}," \
        "PLATFORM_NODES=${PLATFORM_NODES}, PLATFORM_CPUS=${PLATFORM_CPUS}"
}

# Check criteria for K8s platform ready on this node.
# i.e., k8s-infra is configured, kubelet is running
function is_k8s_platform_ready {
    local PASS=0
    local FAIL=1

    # Global variable
    NOT_READY_REASON=""

    # Check that cgroup cpuset k8s-infra has been configured
    if [ ! -e ${CGDIR_K8S} ]; then
        NOT_READY_REASON="k8s-infra not configured"
        return ${FAIL}
    fi

    # Check that kubelet is running and stable
    if systemctl is-active kubelet --quiet; then
        PID=$(systemctl show kubelet.service -p MainPID | \
                awk -vFS='=' '{print $2}')
        if [ ${PID} -eq 0 ]; then
            NOT_READY_REASON="kubelet not running"
            return ${FAIL}
        fi
        up=$(ps -p ${PID} -o etimes= 2>/dev/null | awk '{print $1}')
        if ! { [ -n "${up}" -a ${up} -ge 30 ]; }
        then
            NOT_READY_REASON="kubelet not yet stable"
            return ${FAIL}
        fi
    else
        NOT_READY_REASON="kubelet not running"
        return ${FAIL}
    fi

    LOG "kubelet is ready"
    return ${PASS}
}

# Determine whether this node has 'static' cpu manager policy.
# NOTE: This check assumes that kubelet is already running locally.
function is_static_cpu_manager_policy {
    local PASS=0
    local FAIL=1

    state=$(cat /var/lib/kubelet/cpu_manager_state 2>/dev/null)
    if [[ $state =~ \"policyName\":.?\"static\" ]]; then
        return ${PASS}
    else
        return ${FAIL}
    fi
}

# Check criteria for K8s platform steady-state ready on this node.
# i.e., kube-system pods have recovered, kube application apply
# has completed, nova-compute is running, cinder-volume is running.
# NOTE: This function depends on kubectl commands, so is only
# usable on controllers.
function is_k8s_platform_steady_state_ready {
    local PASS=0
    local FAIL=1
    local this_node=${HOSTNAME}

    # Global variable
    NOT_READY_REASON=""

    # Check that kube-system pods have recovered on this node
    npods=$(kubectl get pods --namespace kube-system --no-headers \
            --field-selector spec.nodeName=${this_node} 2>/dev/null | \
            awk '
BEGIN { n=0; }
!/Completed|Running/ { n+=1 }
END { printf "%d\n", n; }
')
    if [ ${npods} -gt 0 ]; then
        NOT_READY_REASON="${npods} kube-system pods not recovered"
        STABLE=0
        return ${FAIL}
    fi

    # Wait for a few critical openstack pods to be running if this is
    # an openstack-compute-node. This is not an exhaustive list.
    # Make sure that all openstack pods on this node are running.
    labels=$(kubectl get node ${this_node} \
                --no-headers --show-labels 2>/dev/null | awk '{print $NF}')
    if [[ $labels =~ openstack-compute-node=enabled ]]; then
        # nova-compute is one of the last charts to recover after reboot
        PODS=( $(kubectl get pods --namespace openstack --no-headers \
                --selector application=nova,component=compute \
                --field-selector \
                spec.nodeName=${this_node},status.phase=Running 2>/dev/null) )
        if [ ${#PODS[@]} -eq 0 ]; then
            NOT_READY_REASON="nova-compute pod not running"
            STABLE=0
            return ${FAIL}
        fi

        # cinder-volume is one of the last charts to recover after reboot
        PODS=( $(kubectl get pods --namespace openstack --no-headers \
               --selector application=cinder,component=volume \
               --field-selector \
               spec.nodeName=${this_node},status.phase=Running 2>/dev/null) )
        if [ ${#PODS[@]} -eq 0 ]; then
            NOT_READY_REASON="cinder-volume pod not running"
            STABLE=0
            return ${FAIL}
        fi

        # Check that all openstack pods on this node have recovered
        npods=$(kubectl get pods --namespace openstack --no-headers \
                --field-selector spec.nodeName=${this_node} 2>/dev/null | \
                awk '
BEGIN { n=0; }
!/Completed|Running/ { n+=1 }
END { printf "%d\n", n; }
')
        if [ ${npods} -gt 0 ]; then
            NOT_READY_REASON="${npods} openstack pods not recovered"
            STABLE=0
            return ${FAIL}
        fi
    fi

    # Evaluate elapsed time since check criteria pass
    if [ ${STABLE} -eq 0 ]; then
        STABLE=${SECONDS}
    fi
    dt=$(( ${SECONDS} - ${STABLE} ))
    if [ ${dt} -lt ${STABILIZATION_SECONDS} ]; then
        NOT_READY_REASON="stabilization wait"
        return ${FAIL}
    fi

    LOG "K8S is ready"
    return ${PASS}
}

# Get number of DRBD resources started.
# Returns 0 if DRBD not ready.
function number_drbd_resources_started {
    local started

    # Number of started DRBD resources
    started=$(cat /proc/drbd 2>/dev/null | \
                awk '/cs:/ { n+=1; } END {printf "%d\n", n}')
    echo "${started}"
}

# Check criteria for all drbd resources started.
# i.e., see running DRBD worker threads for each configured resource.
function all_drbd_resources_started {
    local PASS=0
    local FAIL=1
    local -i started=0
    local -i resources=0

    # Global variable
    NOT_READY_REASON=""

    # Number of started DRBD resources
    started=$(number_drbd_resources_started)
    if [ ${started} -eq 0 ]; then
        NOT_READY_REASON="no drbd resources started"
        return ${FAIL}
    fi

    # Number of expected DRBD resources
    resources=$(drbdadm sh-resources | \
                awk -vFS='[[:space:]]' 'END {print NF}')
    if [ ${started} -ne ${resources} ]; then
        NOT_READY_REASON="${started} of ${resources} drbd resources started"
        return ${FAIL}
    fi

    return ${PASS}
}

function affine_drbd_tasks {
    local CPUS=$1
    local pidlist

    LOG "Affine drbd tasks, CPUS=${CPUS}"

    # Affine drbd_r_* threads to all cores. The DRBD receiver threads are
    # particularly CPU intensive. Leave the other DRBD threads alone.
    pidlist=$(pgrep drbd_r_)
    for pid in ${pidlist[@]}; do
        taskset --pid --cpu-list ${CPUS} ${pid} > /dev/null 2>&1
    done
}

# Return list of reaffineable pids. This includes all processes, but excludes
# kernel threads, vSwitch, and anything in K8S or qemu/kvm.
function reaffineable_pids {
    local pids_excl
    local pidlist

    pids_excl=$(ps -eL -o pid=,comm= | \
                awk -vORS=',' '/eal-intr-thread|kthreadd/ {print $1}' | \
                sed 's/,$/\n/')
    pidlist=$(ps --ppid ${pids_excl} -p ${pids_excl} --deselect \
                -o pid=,cgroup= | \
                awk '!/k8s-infra|machine.slice/ {print $1; }')
    echo "${pidlist[@]}"
}

function affine_tasks_to_all_cores {
    local pidlist
    local count=0

    LOG "Affine all tasks, CPUS: ${NONISOL_CPUS};" \
        "online=${ONLINE_CPUS} (0x${ONLINE_MASK})," \
        "isol=${ISOL_CPUS}, nonisol=${NONISOL_CPUS} (0x${NONISOL_MASK})"

    pidlist=( $(reaffineable_pids) )
    for pid in ${pidlist[@]}; do
        count=$((${count} + 1))
        taskset --all-tasks --pid --cpu-list \
            ${NONISOL_CPUS} ${pid} > /dev/null 2>&1
    done

    LOG "Affined ${count} processes to all cores."
}

function affine_tasks_to_platform_cores {
    local pidlist
    local count=0

    LOG "Affine all tasks, PLATFORM_CPUS=${PLATFORM_CPUS}"

    pidlist=( $(reaffineable_pids) )
    for pid in ${pidlist[@]}; do
        pid_mask=$(taskset -p $pid 2> /dev/null | awk '{print $6}')
        if [ "${pid_mask}" == "${NONISOL_MASK}" ]; then
            count=$((${count} + 1))
            taskset --all-tasks --pid --cpu-list \
                ${PLATFORM_CPUS} ${pid} > /dev/null 2>&1
        fi
    done

    # Reaffine vSwitch tasks that span multiple cpus to platform cpus
    pidlist=$(ps -eL -o pid=,comm= | awk '/eal-intr-thread/ {print $1}')
    for pid in ${pidlist[@]}; do
        count=$((${count} + 1))
        grep Cpus_allowed_list /proc/${pid}/task/*/status 2>/dev/null | \
            sed 's#/# #g' | awk '/,|-/ {print $4}' | \
            xargs --no-run-if-empty -i{} \
            taskset --pid --cpu-list ${PLATFORM_CPUS} {} > /dev/null 2>&1
    done

    # Reaffine drbd_r_* threads to platform cpus
    affine_drbd_tasks ${PLATFORM_CPUS}

    LOG "Affined ${count} processes to platform cores."
}

function start {
    # Ensure this only runs on AIO
    if ! { [[ "$nodetype" = "controller" ]] && [[ $subfunction = *worker* ]]; }
    then
        LOG "Not AIO, nothing to do."
        return
    fi

    # Abort if another instantiation is already running
    if [ -e ${PIDFILE} ]; then
        PID=$(cat ${PIDFILE})
        if [ -n "${PID}" -a -e /proc/${PID} ]; then
            ERROR "Aborting, ${PID} already running: ${PIDFILE}."
            exit 1
        else
            OUT=$(rm -v -f ${PIDFILE})
            LOG "${OUT}"
        fi
    fi

    LOG "Starting."

    # Create pidfile to indicate the script is running
    echo $$ > ${PIDFILE}

    # Affine all tasks to float on all cores
    affine_tasks_to_all_cores

    # Wait for kubelet to be running
    t0=${SECONDS}
    until is_k8s_platform_ready; do
        dt=$(( ${SECONDS} - ${t0} ))
        if [ ${dt} -ge ${PRINT_INTERVAL_SECONDS} ]; then
            t0=${SECONDS}
            LOG "Recovery wait, elapsed ${SECONDS} seconds." \
                "Reason: ${NOT_READY_REASON}"
        fi
        sleep ${INIT_INTERVAL_SECONDS}
    done

    # Update K8S cpuset so that pods float on all cpus
    # NOTE: dynamic cpuset changes incompatible with static policy
    if ! is_static_cpu_manager_policy; then
        update_cgroup_cpuset_k8s_infra_all
    fi

    # Wait for all DRBD resources to have started. Affine DRBD tasks
    # to float on all cores as we find them.
    until all_drbd_resources_started; do
        started=$(number_drbd_resources_started)
        if [ ${started} -gt 0 ]; then
            affine_drbd_tasks ${NONISOL_CPUS}
        fi
        dt=$(( ${SECONDS} - ${t0} ))
        if [ ${dt} -ge ${PRINT_INTERVAL_SECONDS} ]; then
            t0=${SECONDS}
            LOG "Recovery wait, elapsed ${SECONDS} seconds." \
                "Reason: ${NOT_READY_REASON}"
        fi
        sleep ${INIT_INTERVAL_SECONDS}
    done
    affine_drbd_tasks ${NONISOL_CPUS}

    # Wait until K8s pods have recovered and nova-compute is running
    t0=${SECONDS}
    until is_k8s_platform_steady_state_ready; do
        dt=$(( ${SECONDS} - ${t0} ))
        if [ ${dt} -ge ${PRINT_INTERVAL_SECONDS} ]; then
            t0=${SECONDS}
            LOG "Recovery wait, elapsed ${SECONDS} seconds." \
                "Reason: ${NOT_READY_REASON}"
        fi
        sleep ${CHECK_INTERVAL_SECONDS}
    done

    # Update K8S cpuset to platform cores
    if ! is_static_cpu_manager_policy; then
        update_cgroup_cpuset_k8s_infra_platform
    fi

    # Affine all floating tasks back to platform cores
    affine_tasks_to_platform_cores

    # Remove pidfile after successful completion
    rm -f ${PIDFILE}

    LOG "Complete."
}

function stop {
    LOG "Stopping."

    # Forcibly stop any running instantiation
    if [ -e ${PIDFILE} ]; then
        PID=$(cat ${PIDFILE})
        if [ -n "${PID}" -a -e /proc/${PID} ]; then
            LOG "Stopping ${PID}: ${PIDFILE}."
            kill -9 ${PID}
            timeout 20 tail --pid=${PID} -f /dev/null
        fi
        OUT=$(rm -v -f ${PIDFILE})
        LOG "${OUT}"
    fi
}

function status {
    :
}

function reset {
    :
}

if [ ${UID} -ne 0 ]; then
    ERROR "Need sudo/root permission."
    exit 1
fi

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart|force-reload|reload)
        stop
        start
        ;;
    status)
        status
        ;;
    reset)
        reset
        ;;
    *)
        echo "Usage: $0 {start|stop|force-reload|restart|reload|status|reset}"
        exit 1
        ;;
esac

exit 0
