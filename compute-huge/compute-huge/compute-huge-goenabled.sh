#!/bin/bash
#
# Copyright (c) 2014,2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

#
# compute-huge.sh "goenabled" check.
# 
# If a problem was detected during configuration of huge pages and compute
# resources then the board is not allowed to enable.
#
COMPUTE_HUGE_GOENABLED="/var/run/compute_huge_goenabled"

source "/etc/init.d/log_functions.sh"
source "/usr/bin/tsconfig"

if [ -e ${VOLATILE_COMPUTE_CONFIG_COMPLETE} -a ! -f ${COMPUTE_HUGE_GOENABLED} ]; then
    log_error "compute-huge.sh CPU configuration check failed. Failing goenabled check."
    exit 1
fi

exit 0
