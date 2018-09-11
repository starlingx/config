#!/bin/bash
#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# SysInv "goenabled" check.
# Wait for sysinv information to be posted prior to allowing goenabled.

NAME=$(basename $0)
SYSINV_READY_FLAG=/var/run/.sysinv_ready

logfile=/var/log/platform.log

function LOG {
    logger "$NAME: $*"
    echo "`date "+%FT%T"`: $NAME: $*" >> $logfile
}

count=0
while [ $count -le 45 ]; do
    if [ -f $SYSINV_READY_FLAG ]; then
        LOG "SysInv is ready.  Passing goenabled check."
        echo "SysInv goenabled iterations PASS $count"
        LOG "SysInv goenabled iterations PASS $count"
        exit 0
    fi
    sleep 1
    count=$(($count+1))
done

echo "SysInv goenabled iterations FAIL $count"

LOG "SysInv is not ready. Continue."
exit 0
