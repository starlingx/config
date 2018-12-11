#!/bin/bash
################################################################################
# Copyright (c) 2013 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
################################################################################
#
# ps-sched.sh -- gives detailed task listing with scheduling attributes
#             -- this is cpu and scheduling intensive version (shell/taskset based)
#                (note: does not print fields 'group' or 'timeslice')

printf "%6s %6s %6s %1c %2s %4s %6s %4s %-24s %2s %-16s %s\n" "PID" "TID" "PPID" "S" "PO" "NICE" "RTPRIO" "PR" "AFFINITY" "P" "COMM" "COMMAND"
ps -eL -o pid=,lwp=,ppid=,state=,class=,nice=,rtprio=,priority=,psr=,comm=,command= | \
    while read pid tid ppid state policy nice rtprio priority psr comm command; do
        bitmask=$(taskset -p $tid 2>/dev/null)
        aff=${bitmask##*: }
        if [ -z "${aff}" ]; then
            aff="0x0"
        else
            aff="0x${aff}"
        fi
        printf "%6d %6d %6d %1c %2s %4s %6s %4d %-24s %2d %-16s %s\n" $pid $tid $ppid $state $policy $nice $rtprio $priority $aff $psr $comm "$command"
    done

exit 0
