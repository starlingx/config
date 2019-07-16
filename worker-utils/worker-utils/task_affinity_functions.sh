#!/bin/bash
################################################################################
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
################################################################################
#
### BEGIN INIT INFO
# Provides:          task_affinity_functions
# Required-Start:
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: task_affinity_functions
### END INIT INFO

# Define minimal path
PATH=/bin:/usr/bin:/usr/local/bin

. /etc/platform/platform.conf
LOG_FUNCTIONS=${LOG_FUNCTIONS:-"/etc/init.d/log_functions.sh"}
CPUMAP_FUNCTIONS=${CPUMAP_FUNCTIONS:-"/etc/init.d/cpumap_functions.sh"}
[[ -e ${LOG_FUNCTIONS} ]] && source ${LOG_FUNCTIONS}
[[ -e ${CPUMAP_FUNCTIONS} ]] && source ${CPUMAP_FUNCTIONS}

# Enable debug logs and tag them
LOG_DEBUG=1
TAG="TASKAFFINITY:"

TASK_AFFINING_INCOMPLETE="/etc/platform/.task_affining_incomplete"
N_CPUS=$(getconf _NPROCESSORS_ONLN)
FULLSET_CPUS="0-"$((N_CPUS-1))
FULLSET_MASK=$(cpulist_to_cpumap ${FULLSET_CPUS} ${N_CPUS})
PLATFORM_CPUS=$(platform_expanded_cpu_list)
PLATFORM_CPULIST=$(platform_expanded_cpu_list| \
                    perl -pe 's/(\d+)-(\d+)/join(",",$1..$2)/eg'| \
                    sed 's/,/ /g')
VSWITCH_CPULIST=$(get_vswitch_cpu_list| \
                    perl -pe 's/(\d+)-(\d+)/join(",",$1..$2)/eg'| \
                    sed 's/,/ /g')
if [[ $vswitch_type =~ none ]]; then
    VSWITCH_CPULIST=""
fi

IDLE_MARK=95.0
KERNEL=$(uname -a)

################################################################################
# Check if a given core is one of the platform cores
################################################################################
function is_platform_core {
    local core=$1
    for CPU in ${PLATFORM_CPULIST}; do
        if [ $core -eq $CPU ]; then
            return 1
        fi
    done
    return 0
}

################################################################################
# Check if a given core is one of the vswitch cores
################################################################################
function is_vswitch_core {
    local core=$1
    for CPU in ${VSWITCH_CPULIST}; do
        if [ $core -eq $CPU ]; then
            return 1
        fi
    done
    return 0
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

################################################################################
# The following function can be called by any platform service that needs to
# temporarily make use of idle VM cores to run a short-duration, service
# critical and cpu intensive operation in AIO. For instance, sm can levearage
# the idle cores to speed up swact activity.
#
# At the end of the operation, regarless of the result, the service must be
# calling function affine_tasks_to_platform_cores to re-affine platform tasks
# back to their assigned core(s).
#
# Kernel, vswitch and VM related tasks are untouched.
################################################################################
function affine_tasks_to_idle_cores {
    local cpulist
    local cpuocc_list
    local vswitch_pid
    local pidlist
    local idle_cpulist
    local platform_cpus
    local rc=0
    local cpu=0

    if [ -f ${TASK_AFFINING_INCOMPLETE} ]; then
        read cpulist < ${TASK_AFFINING_INCOMPLETE}
        log_debug "${TAG} Tasks have already been affined to CPU ($cpulist)."
        return 0
    fi

    if [[ "${KERNEL}" == *" RT "* ]]; then
        return 0
    fi

    # Compile a list of cpus with idle percentage greater than 95% in the last
    # 5 seconds.
    cpuocc_list=($(sar -P ALL 1 5|grep Average|awk '{if(NR>2)print $8}'))

    for idle_value in ${cpuocc_list[@]}; do
        is_vswitch_core $cpu
        if [ $? -eq 1 ]; then
            cpu=$(($cpu+1))
            continue
        fi

        is_platform_core $cpu
        if [ $? -eq 1 ]; then
            # Platform core is added to the idle list by default
            idle_cpulist=$idle_cpulist$cpu","
        else
            # Non platform core is added to the idle list if it is more
            # than 95% idle
            if [[ $(echo "$idle_value > ${IDLE_MARK}"|bc) -eq 1 ]]; then
                idle_cpulist=$idle_cpulist$cpu","
            fi
        fi
        cpu=$(($cpu+1))
    done

    idle_cpulist=$(echo $idle_cpulist|sed 's/.$//')

    log_debug "${TAG} Affining all tasks to idle CPU ($idle_cpulist)"
    pidlist=( $(reaffineable_pids) )
    for pid in ${pidlist[@]}; do
        taskset --all-tasks --pid --cpu-list \
            ${idle_cpulist} ${pid} > /dev/null 2>&1
    done

    # Save the cpu list to the temp file which will be read and removed when
    # tasks are reaffined to the platform cores later on.
    echo $idle_cpulist > ${TASK_AFFINING_INCOMPLETE}
    return $rc
}

################################################################################
# The following function is called by sm at the end of swact sequence
# to re-affine management tasks back to the platform cores.
################################################################################
function affine_tasks_to_platform_cores {
    local cpulist
    local pidlist
    local rc=0
    local count=0

    if [ ! -f ${TASK_AFFINING_INCOMPLETE} ]; then
        dbg_str="${TAG} Either tasks have never been affined to all/idle"
        dbg_str="${TAG} cores or they have already been reaffined to"
        dbg_str="${TAG} platform cores."
        log_debug "$dbg_str"
        return 0
    fi

    read cpulist < ${TASK_AFFINING_INCOMPLETE}

    log_debug "${TAG} Reaffining tasks to platform cores (${PLATFORM_CPUS})..."
    pidlist=( $(reaffineable_pids) )
    for pid in ${pidlist[@]}; do
        taskset --all-tasks --pid --cpu-list \
            ${PLATFORM_CPUS} ${pid} > /dev/null 2>&1
    done

    # Reaffine vSwitch tasks that span multiple cpus to platform cpus
    pidlist=$(ps -eL -o pid=,comm= | awk '/eal-intr-thread/ {print $1}')
    for pid in ${pidlist[@]}; do
        grep Cpus_allowed_list /proc/${pid}/task/*/status 2>/dev/null | \
            sed 's#/# #g' | awk '/,|-/ {print $4}' | \
            xargs --no-run-if-empty -i{} \
            taskset --pid --cpu-list ${PLATFORM_CPUS} {} > /dev/null 2>&1
    done

    rm -rf ${TASK_AFFINING_INCOMPLETE}
    return $rc
}

################################################################################
# The following function can be leveraged by cron tasks
################################################################################
function get_most_idle_core {
    local cpuocc_list
    local cpu=0
    local most_idle_value=${IDLE_MARK}
    local most_idle_cpu=0

    if [[ "${KERNEL}" == *" RT "* ]]; then
        echo $cpu
        return
    fi

    cpuocc_list=($(sar -P ALL 1 5|grep Average|awk '{if(NR>2)print $8}'))

    for idle_value in ${cpuocc_list[@]}; do
        is_vswitch_core $cpu
        if [ $? -eq 1 ]; then
            cpu=$(($cpu+1))
            continue
        fi

        if [ $(echo "$idle_value > $most_idle_value"|bc) -eq 1 ]; then
            most_idle_value=$idle_value
            most_idle_cpu=$cpu
        fi
        cpu=$(($cpu+1))
    done

    echo $most_idle_cpu
}
