#!/bin/bash
###############################################################################
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
###############################################################################
#
### BEGIN INIT INFO
# Provides:          affine-tasks
# Required-Start:
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: affine tasks
# Description:       This script will affine tasks to the platform cores of the
#       host. This ensures that system processes are constrained to platform
#       cores and will not run on cores with VMs/containers.
### END INIT INFO


. /usr/bin/tsconfig
. /etc/init.d/task_affinity_functions.sh

log ()
{
    logger -p local1.info -t affine_tasks $@
    echo affine_tasks: "$@"
}

start ()
{
    log "Starting affine_tasks. Reaffining tasks to platform cores..."
    if [ ! -f ${INITIAL_CONFIG_COMPLETE_FLAG} ]; then
        log "Initial Configuration incomplete. Skipping affining tasks."
        exit 0
    fi
    # TODO: Should revisit this since this leaves a few lingering floating
    # tasks and does not really work with cgroup cpusets.
    # Comment out for now. Cleanup required.
    ##affine_tasks_to_platform_cores
    ##[[ $? -eq 0 ]] && log "Tasks re-affining done." || log "Tasks re-affining failed."
}

stop ()
{
    log "Stopping affine_tasks..."
}

status()
{
    :
}

reset()
{
    :
}

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
