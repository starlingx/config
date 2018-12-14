#!/bin/bash
#
# Copyright (c) 2014,2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

#
# worker "goenabled" check.
#
# If a problem was detected during configuration of worker
# resources then the board is not allowed to enable.
#
WORKER_GOENABLED="/var/run/worker_goenabled"

source "/etc/init.d/log_functions.sh"
source "/usr/bin/tsconfig"

if [ -e ${VOLATILE_WORKER_CONFIG_COMPLETE} -a ! -f ${WORKER_GOENABLED} ]; then
    log_error "Worker manifest CPU configuration check failed. Failing goenabled check."
    exit 1
fi

exit 0
