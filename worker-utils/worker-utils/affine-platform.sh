#!/bin/bash
################################################################################
# Copyright (c) 2013 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
################################################################################
# Define minimal path
PATH=/bin:/usr/bin:/usr/local/bin

LOG_FUNCTIONS=${LOG_FUNCTIONS:-"/etc/init.d/log_functions.sh"}
CPUMAP_FUNCTIONS=${CPUMAP_FUNCTIONS:-"/etc/init.d/cpumap_functions.sh"}
TASK_AFFINITY_FUNCTIONS=${TASK_AFFINITY_FUNCTIONS:-"/etc/init.d/task_affinity_functions.sh"}
source /etc/init.d/functions
[[ -e ${LOG_FUNCTIONS} ]] && source ${LOG_FUNCTIONS}
[[ -e ${CPUMAP_FUNCTIONS} ]] && source ${CPUMAP_FUNCTIONS}
[[ -e ${TASK_AFFINITY_FUNCTIONS} ]] && source ${TASK_AFFINITY_FUNCTIONS}
linkname=$(readlink -n -f $0)
scriptname=$(basename $linkname)

# Enable debug logs
LOG_DEBUG=1

. /etc/platform/platform.conf

################################################################################
# Affine all running tasks to the CPULIST provided in the first parameter.
################################################################################
function affine_tasks {
    local CPULIST=$1
    local PIDLIST
    local RET=0

    # Affine non-kernel-thread tasks (excluded [kthreadd] and its children) to all available
    # cores. They will be reaffined to platform cores later on as part of nova-compute
    # launch.
    log_debug "Affining all tasks to all available CPUs..."
    affine_tasks_to_all_cores
    RET=$?
    if [ $RET -ne 0 ]; then
        log_error "Some tasks failed to be affined to all cores."
    fi

    # Get number of logical cpus
    N_CPUS=$(cat /proc/cpuinfo 2>/dev/null | \
        awk '/^[pP]rocessor/ { n +=1 } END { print (n>0) ? n : 1}')

    # Calculate platform cores cpumap
    PLATFORM_COREMASK=$(cpulist_to_cpumap ${CPULIST} ${N_CPUS})

    # Set default IRQ affinity
    echo ${PLATFORM_COREMASK} > /proc/irq/default_smp_affinity

    # Affine all PCI/MSI interrupts to platform cores; this overrides
    # irqaffinity boot arg, since that does not handle IRQs for PCI devices
    # on numa nodes that do not intersect with platform cores.
    PCIDEVS=/sys/bus/pci/devices
    declare -a irqs=()
    irqs+=($(cat ${PCIDEVS}/*/irq 2>/dev/null | xargs))
    irqs+=($(ls ${PCIDEVS}/*/msi_irqs 2>/dev/null | grep -E '^[0-9]+$' | xargs))
    # flatten list of irqs, removing duplicates
    irqs=($(echo ${irqs[@]} | tr ' ' '\n' | sort -nu))
    log_debug "Affining all PCI/MSI irqs(${irqs[@]}) with cpus (${CPULIST})"
    for i in ${irqs[@]}; do
        /bin/bash -c "[[ -e /proc/irq/${i} ]] && echo ${CPULIST} > /proc/irq/${i}/smp_affinity_list" 2>/dev/null
    done
    if [[ "$subfunction" == *"worker,lowlatency" ]]; then
        # Affine work queues to platform cores
        echo ${PLATFORM_COREMASK} > /sys/devices/virtual/workqueue/cpumask
        echo ${PLATFORM_COREMASK} > /sys/bus/workqueue/devices/writeback/cpumask

        # On low latency compute reassign the per cpu threads rcuc, ksoftirq,
        # ktimersoftd to FIFO along with the specified priority
        PIDLIST=$( ps -e -p 2 |grep rcuc | awk '{ print $1; }')
        for PID in ${PIDLIST[@]}; do
            chrt -p -f 4 ${PID}  2>/dev/null
        done

        PIDLIST=$( ps -e -p 2 |grep ksoftirq | awk '{ print $1; }')
        for PID in ${PIDLIST[@]}; do
            chrt -p -f 2 ${PID} 2>/dev/null
        done

        PIDLIST=$( ps -e -p 2 |grep ktimersoftd | awk '{ print $1; }')
        for PID in ${PIDLIST[@]}; do
            chrt -p -f 3 ${PID} 2>/dev/null
        done
    fi

    return 0
}

################################################################################
# Start Action
################################################################################
function start {
    local RET=0

    echo -n "Starting ${scriptname}: "

    ## Check whether we are root (need root for taskset)
    if [ $UID -ne 0 ]; then
        log_error "require root or sudo"
        RET=1
        return ${RET}
    fi

    ## Define platform cpulist to be thread siblings of core 0
    PLATFORM_CPULIST=$(get_platform_cpu_list)

    # Affine all tasks to platform cpulist
    affine_tasks ${PLATFORM_CPULIST}
    RET=$?
    if [ ${RET} -ne 0 ]; then
        log_error "Failed to affine tasks ${PLATFORM_CPULIST}, rc=${RET}"
        return ${RET}
    fi

    print_status ${RET}
    return ${RET}
}

################################################################################
# Stop Action - don't do anything
################################################################################
function stop {
    local RET=0
    echo -n "Stopping ${scriptname}: "
    print_status ${RET}
    return ${RET}
}

################################################################################
# Restart Action
################################################################################
function restart {
    stop
    start
}

################################################################################
# Main Entry
#
################################################################################
case "$1" in
start)
    start
    ;;
stop)
    stop
    ;;
restart|reload)
    restart
    ;;
status)
    echo -n "OK"
    ;;
*)
    echo $"Usage: $0 {start|stop|restart|reload|status}"
    exit 1
esac

exit $?
