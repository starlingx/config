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
N_CPUS=$(cat /proc/cpuinfo 2>/dev/null | \
            awk '/^[pP]rocessor/ { n +=1 } END { print (n>0) ? n : 1}')
FULLSET_CPUS="0-"$((N_CPUS-1))
FULLSET_MASK=$(cpulist_to_cpumap ${FULLSET_CPUS} ${N_CPUS})
PLATFORM_CPUS=$(get_platform_cpu_list)
PLATFORM_CPULIST=$(get_platform_cpu_list| \
                    perl -pe 's/(\d+)-(\d+)/join(",",$1..$2)/eg'| \
                    sed 's/,/ /g')
VSWITCH_CPULIST=$(get_vswitch_cpu_list| \
                    perl -pe 's/(\d+)-(\d+)/join(",",$1..$2)/eg'| \
                    sed 's/,/ /g')
IDLE_MARK=95.0
KERNEL=`uname -a`

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

################################################################################
# An audit and corrective action following a swact
################################################################################
function audit_and_reaffine {
    local mask=$1
    local cmd_str=""
    local tasklist

    cmd_str="ps-sched.sh|awk '(\$9==\"$mask\") {print \$2}'"

    tasklist=($(eval $cmd_str))
    # log_debug "cmd str = $cmd_str"
    log_debug "${TAG} There are ${#tasklist[@]} tasks to reaffine."

    for task in ${tasklist[@]}; do
        taskset -acp ${PLATFORM_CPUS} $task &> /dev/null
        rc=$?
        [[ $rc -ne 0 ]] && log_error "Failed to set CPU affinity for pid $pid, rc=$rc"
    done
    tasklist=($(eval $cmd_str))
    [[ ${#tasklist[@]} -eq 0 ]] && return 0 || return 1
}

################################################################################
# The following function is used to verify that any sleeping management tasks
# that are on non-platform cores can be migrated to platform cores as soon as
# they are scheduled. It can be invoked either manually or from goenableCompute
# script as a scheduled job (with a few minute delay) if desired.
# The induced tasks migration should be done after all VMs have been restored
# following a host reboot in AIO, hence the delay.
################################################################################
function move_inactive_threads_to_platform_cores {
    local tasklist
    local cmd_str=""

    # Compile a list of non-kernel & non-vswitch/VM related threads that are not
    # on platform cores.
    # e.g. if the platform cpulist value is "0 8", the resulting command to be
    # evaluated should look like this:
    # ps-sched.sh|grep -v vswitch|awk '($10!=0 && $10!=8 && $3!=2) {if(NR>1)print $2}'
    cmd_str="ps-sched.sh|grep -v vswitch|awk '("
    for cpu_num in ${PLATFORM_CPULIST}; do
        cmd_str=$cmd_str"\$10!="${cpu_num}" && "
    done
    cmd_str=$cmd_str"\$3!=2) {if(NR>1)print \$2}'"
    echo "selection string = $cmd_str"
    tasklist=($(eval $cmd_str))
    log_debug "${TAG} There are ${#tasklist[@]} number of tasks to be moved."

    # These sleep tasks are stuck on the wrong core(s). They need to be woken up
    # so they can be migrated to the right ones. Attaching and detaching strace
    # momentarily to the task does the trick.
    for task in ${tasklist[@]}; do
        strace -p $task 2>/dev/null &
        pid=$!
        sleep 0.1
        kill -SIGINT $pid
    done
    tasklist=($(eval $cmd_str))
    [[ ${#tasklist[@]} -eq 0 ]] && return 0 || return 1
}

################################################################################
# The following function is called by affine-platform.sh to affine tasks to
# all available cores during initial startup and subsequent host reboots.
################################################################################
function affine_tasks_to_all_cores {
    local pidlist
    local rc=0

    if [[ "${KERNEL}" == *" RT "* ]]; then
        return 0
    fi

    log_debug "${TAG} Affining all tasks to CPU (${FULLSET_CPUS})"

    pidlist=$(ps --ppid 2 -p 2 --deselect -o pid= | awk '{ print $1; }')
    for pid in ${pidlist[@]}; do
        ppid=$(ps -o ppid= -p $pid |tr -d '[:space:]')
        if [ -z $ppid ] || [ $ppid -eq 2 ]; then
            continue
        fi
        log_debug "Affining pid $pid, parent pid = $ppid"
        taskset --all-tasks --pid --cpu-list ${FULLSET_CPUS} $pid &> /dev/null
        rc=$?
        [[ $rc -ne 0 ]] && log_error "Failed to set CPU affinity for pid $pid, rc=$rc"
    done
    # Write the cpu list to a temp file which will be read and removed when
    # the tasks are reaffined back to platform cores later on.
    echo ${FULLSET_CPUS} > ${TASK_AFFINING_INCOMPLETE}

    return $rc
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
      # Non platform core is added to the idle list if it is more than 95% idle
            [[ $(echo "$idle_value > ${IDLE_MARK}"|bc) -eq 1 ]] && idle_cpulist=$idle_cpulist$cpu","
        fi
        cpu=$(($cpu+1))
    done

    idle_cpulist=$(echo $idle_cpulist|sed 's/.$//')
    platform_affinity_mask=$(cpulist_to_cpumap ${PLATFORM_CPUS} ${N_CPUS} \
                            |awk '{print tolower($0)}')

    log_debug "${TAG} Affining all tasks to idle CPU ($idle_cpulist)"

    vswitch_pid=$(pgrep vswitch)
    pidlist=$(ps --ppid 2 -p 2 --deselect -o pid= | awk '{ print $1; }')
    for pid in ${pidlist[@]}; do
        ppid=$(ps -o ppid= -p $pid |tr -d '[:space:]')
        if [ -z $ppid ] || [ $ppid -eq 2 ] || [ "$pid" = "$vswitch_pid" ]; then
            continue
        fi
        pid_affinity_mask=$(taskset -p $pid | awk '{print $6}')
        if [ "${pid_affinity_mask}" == "${platform_affinity_mask}" ]; then
            # log_debug "Affining pid $pid to idle cores..."
            taskset --all-tasks --pid --cpu-list $idle_cpulist $pid &> /dev/null
            rc=$?
            [[ $rc -ne 0 ]] && log_error "Failed to set CPU affinity for pid $pid, rc=$rc"
        fi
    done

    # Save the cpu list to the temp file which will be read and removed when
    # tasks are reaffined to the platform cores later on.
    echo $idle_cpulist > ${TASK_AFFINING_INCOMPLETE}
    return $rc
}

################################################################################
# The following function is called by either:
# a) nova-compute wrapper script during AIO system initial bringup or reboot
# or
# b) sm at the end of swact sequence
# to re-affine management tasks back to the platform cores.
################################################################################
function affine_tasks_to_platform_cores {
    local cpulist
    local pidlist
    local rc=0
    local count=0

    if [ ! -f ${TASK_AFFINING_INCOMPLETE} ]; then
        dbg_str="${TAG} Either tasks have never been affined to all/idle cores or"
        dbg_str=$dbg_str" they have already been reaffined to platform cores."
        log_debug "$dbg_str"
        return 0
    fi

    read cpulist < ${TASK_AFFINING_INCOMPLETE}
    affinity_mask=$(cpulist_to_cpumap $cpulist ${N_CPUS}|awk '{print tolower($0)}')

    log_debug "${TAG} Reaffining tasks to platform cores (${PLATFORM_CPUS})..."
    pidlist=$(ps --ppid 2 -p 2 --deselect -o pid= | awk '{ print $1; }')
    for pid in ${pidlist[@]}; do
        # log_debug "Processing pid $pid..."
        pid_affinity_mask=$(taskset -p $pid | awk '{print $6}')
        # Only management tasks need to be reaffined. Kernel, vswitch and VM related
        # tasks were not affined previously so they should have different affinity
        # mask(s).
        if [ "${pid_affinity_mask}" == "${affinity_mask}" ]; then
            count=$(($count+1))
            # log_debug "Affining pid $pid to platform cores..."
            taskset --all-tasks --pid --cpu-list ${PLATFORM_CPUS} $pid &> /dev/null
            rc=$?
            [[ $rc -ne 0 ]] && log_error "Failed to set CPU affinity for pid $pid, rc=$rc"
        fi
    done

    # A workaround for lack of "end of swact" state
    fullmask=$(echo ${FULLSET_MASK} | awk '{print tolower($0)}')
    if [ "${affinity_mask}" != "${fullmask}" ]; then
        log_debug "${TAG} Schedule an audit and cleanup"
        (sleep 60; audit_and_reaffine "0x"$affinity_mask) &
    fi

    rm -rf ${TASK_AFFINING_INCOMPLETE}
    log_debug "${TAG} $count tasks were reaffined to platform cores."

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
