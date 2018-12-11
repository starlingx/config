#!/bin/bash
################################################################################
# Copyright (c) 2015-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
################################################################################
#
# Purpose:
#   Affine the interface IRQ to specified cpulist.
#
# Usage: /usr/bin/affine-interrupts.sh interface cpulist
#
# Define minimal path
PATH=/bin:/usr/bin:/usr/local/bin

# logger setup
WHOAMI=`basename $0`
LOG_FACILITY=user
LOG_PRIORITY=info
TMPLOG=/tmp/${WHOAMI}.log

# LOG() - generates log and puts in temporary file
function LOG {
    logger -t "${0##*/}[$$]" -p ${LOG_FACILITY}.${LOG_PRIORITY} "$@"
    echo "${0##*/}[$$]" "$@" >> ${TMPLOG}
}
function INFO {
    MSG="INFO"
    LOG "${MSG} $@"
}
function ERROR {
    MSG="ERROR"
    LOG "${MSG} $@"
}

if [ "$#" -ne 2 ]; then
    ERROR "Interface name and cpulist are required"
    exit 1
fi

interface=$1
cpulist=$2

# Find PCI device matching interface, keep last matching device name
dev=$(find /sys/devices -name "${interface}" | \
    perl -ne 'print $1 if /([[:xdigit:]]{4}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[[:xdigit:]])\/[[:alpha:]]/;')

# Obtain all IRQs for this device
irq=$(cat /sys/bus/pci/devices/${dev}/irq 2>/dev/null)
msi_irqs=$(ls /sys/bus/pci/devices/${dev}/msi_irqs 2>/dev/null | xargs)

INFO $LINENO "affine ${interface} (dev:${dev} irq:${irq} msi_irqs:${msi_irqs}) with cpus (${cpulist})"

for i in $(echo "${irq} ${msi_irqs}"); do echo $i; done | \
    xargs --no-run-if-empty -i{} \
    /bin/bash -c "[[ -e /proc/irq/{} ]] && echo ${cpulist} > /proc/irq/{}/smp_affinity_list" 2>/dev/null

exit 0
