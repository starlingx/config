#!/bin/bash
#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# This migration script is used to toggle on and off during
# upgrade. Using system drdbsync-modify CLI to toggle drbd secure
# configuration.
# - During migrate
#   - Deactivate drbd secure config to keep compatibility to
#     synchonize with other drbd node, which is not upgraded yet
# - During activate
#   - Activate drbd secure config on both controllers since
#     both controllers (DX,STD,STORAGE) are already upgraded in
#     activate phase.
# - During rollback
#   - Since rollback restores the database and puppet hieradata
#     from previous release, it is not necessary to develop an
#     activate-rollback script for these actions.
#
# Note: The 'drbdsync-modify' command modifies an entry in the
#       system configuration database, located in a specific directory
#       related to the current platform version. Potential paths could
#       include '/var/lib/postgresql/<current version>/'.
NAME=$(basename $0)

# The migration scripts are passed these parameters:
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

RETRY_INTERVAL=10
RETRY_CNT=10

# This will log to /var/log/platform.log
function log {
    logger -p local1.info $1
}

function get_api_token {
    curl -v -X POST "${1}/auth/tokens" \
    --header 'Content-Type: application/json' \
    --data '{
        "auth": {
            "identity": {
                "methods": [
                    "password"
                ],
                "password": {
                    "user": {
                        "domain": {
                            "name": "Default"
                        },
                        "name": "'${2}'",
                        "password": "'${3}'"
                    }
                }
            },
            "scope": {
                "project": {
                    "domain": {
                        "name": "Default"
                    },
                    "name": "admin"
                }
            }
        }
    }' 2>&1 | sed -n 's/.*[t|T]oken: \(.*\)/\1/p'
}

log "${NAME}: Starting drbdconfig secure toggle from release ${FROM_RELEASE} to ${TO_RELEASE} with action ${ACTION}"

if [[ "${ACTION}" == "activate" ]] && [[ "${TO_RELEASE}" == "24.09" ]]; then
    source /etc/platform/openrc

    while [ ${RETRY_CNT} -ge 0 ];
    do
        TOKEN=$(get_api_token "${OS_AUTH_URL}" "${OS_USERNAME}" "${OS_PASSWORD}")
        PARAMETERS_JSON=$(curl -s -X GET "http://controller:6385/v1/service_parameter/" -H "X-Auth-Token: ${TOKEN}")
        DRBDSYNC_SECURE=$(echo "${PARAMETERS_JSON}" | sed -n 's/.*"section": "drbd", "name": "secure", "value": "\([^"]*\)".*/\1/p')

        if [[ "${DRBDSYNC_SECURE}"  == 'True' ]]; then
            log "${NAME}: drbdconfig secure toggle is True."
            exit 0
        fi

        if  system drbdsync-modify --secure True; then
            log "${NAME}: drbdconfig secure toggle is True."
            exit 0
        fi

        if [ ${RETRY_CNT} -gt 0 ]; then
            log "${NAME}: retrying drbdconfig secure toggle ( remaining ${RETRY_CNT} )."
            RETRY_CNT=$((RETRY_CNT-1))
            sleep ${RETRY_INTERVAL}
        else
            log "${NAME}: drbdconfig secure toggle was not possible."
            exit 1
        fi
    done
fi
