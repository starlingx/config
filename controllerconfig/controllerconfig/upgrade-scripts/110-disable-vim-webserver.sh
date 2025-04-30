#!/bin/bash
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script disables NFV-VIM Web Server. From version 25.x onwards,
# the web server will stay disabled by default in order to optimize
# memory and CPU consumption of the host.
#
# The user can manually reactivate it issuing the command:
# "sm-provision service-group-member vim-services vim-webserver"
#

# shellcheck disable=SC2206

# The script receives these parameters:
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

SOFTWARE_LOG_PATH="/var/log/software.log"
FROM_RELEASE_ARR=(${FROM_RELEASE//./ })
FROM_RELEASE_MAJOR=${FROM_RELEASE_ARR[0]}
TO_RELEASE_ARR=(${TO_RELEASE//./ })
TO_RELEASE_MAJOR=${TO_RELEASE_ARR[0]}

# Default logging method extracted from script #02
function log {
    echo "$(date -Iseconds | cut -d'+' -f1): ${NAME}[$$]: INFO: $*" \
        >> "${SOFTWARE_LOG_PATH}" 2>&1
}

if [[ "${ACTION}" == "migrate" ]] && \
   [ ${FROM_RELEASE_MAJOR} -lt 25 ] && \
   [ ${TO_RELEASE_MAJOR} -ge 25 ]; then

    log Disabling the NFV-VIM Web Server...

    sm-deprovision service-group-member vim-services vim-webserver
    ret_value=$?

    [ $ret_value -eq 0 ] && log NFV-VIM Web Server successfully disabled
    exit $ret_value

else
    log No actions required from $FROM_RELEASE to $TO_RELEASE with action $ACTION
fi
