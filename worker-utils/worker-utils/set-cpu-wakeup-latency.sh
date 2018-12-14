#!/bin/bash

#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Purpose: set PM QoS resume latency constraints for CPUs.
# Usage: /usr/bin/set-cpu-wakeup-latency.sh policy cpulist
# policy may be either "low" or "high" to set appropriate latency.
# "low" means HALT (C1) is the deepest C-state we allow the CPU to enter.
# "high" means we allow the CPU to sleep as deeply as possible.
# cpulist is for specifying a numerical list of processors.
# It may contain multiple items, separated by comma, and ranges.
# For example, 0,5,7,9-11.

# Define minimal path
PATH=/bin:/usr/bin:/usr/local/bin

LOG_FUNCTIONS=${LOG_FUNCTIONS:-"/etc/init.d/log_functions.sh"}
CPUMAP_FUNCTIONS=${CPUMAP_FUNCTIONS:-"/etc/init.d/cpumap_functions.sh"}
[[ -e ${LOG_FUNCTIONS} ]] && source ${LOG_FUNCTIONS}
[[ -e ${CPUMAP_FUNCTIONS} ]] && source ${CPUMAP_FUNCTIONS}

if [ $UID -ne 0 ]; then
    log_error "$0 requires root or sudo privileges"
    exit 1
fi

if [ "$#" -ne 2 ]; then
    log_error "$0 requires policy and cpulist parameters"
    exit 1
fi

POLICY=$1
CPU_LIST=$2
NUMBER_OF_CPUS=$(getconf _NPROCESSORS_CONF 2>/dev/null)
STATUS=1

for CPU_NUM in $(expand_sequence "$CPU_LIST" " "); do
    # Check that we are not setting PM QoS policy for non-existing CPU
    if [ "$CPU_NUM" -lt "0" ] || [ "$CPU_NUM" -ge "$NUMBER_OF_CPUS" ]; then
        log_error "CPU number ${CPU_NUM} is invalid, available CPUs are 0-${NUMBER_OF_CPUS-1}"
        exit 1
    fi

    # Obtain CPU wakeup latencies for all C-states available starting from operating state to deepest sleep
    declare -a LIMITS=()
    LIMITS+=($(cat /sys/devices/system/cpu/cpu${CPU_NUM}/cpuidle/state*/latency 2>/dev/null | xargs | sort))
    if [ ${#LIMITS[@]} -eq 0 ]; then
        log_debug "Failed to get PM QoS latency limits for CPU ${CPU_NUM}"
    fi

    # Select appropriate CPU wakeup latency based on "low" or "high" policy
    case "${POLICY}" in
        "low")
            # Get first sleep state for "low" policy
            if [ ${#LIMITS[@]} -eq 0 ]; then
                LATENCY=1
            else
                LATENCY=${LIMITS[1]}
            fi
            ;;
        "high")
            # Get deepest sleep state for "high" policy
            if [ ${#LIMITS[@]} -eq 0 ]; then
                LATENCY=1000
            else
                LATENCY=${LIMITS[${#LIMITS[@]}-1]}
            fi
            ;;
        *)
            log_error "Policy is invalid, can be either low or high"
            exit 1
    esac

    # Set the latency for paricular CPU
    echo ${LATENCY} > /sys/devices/system/cpu/cpu${CPU_NUM}/power/pm_qos_resume_latency_us 2>/dev/null
    RET_VAL=$?
    if [ ${RET_VAL} -ne 0 ]; then
        log_error "Failed to set PM QoS latency for CPU ${CPU_NUM}, rc=${RET_VAL}"
        continue
    else
        log_debug "Succesfully set PM QoS latency for CPU ${CPU_NUM}, rc=${RET_VAL}"
        STATUS=0
    fi
done

exit ${STATUS}
