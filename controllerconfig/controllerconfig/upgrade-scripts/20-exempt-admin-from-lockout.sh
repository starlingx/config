#!/bin/bash
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will call keystone user PATCH API to set
# "ignore_lockout_failure_attempts" option for admin user, so that admin user
# is exempted from failed auth lockout.
#
# This script can be removed in the release that follows 20.06.
#

NAME=$(basename $0)

# The migration scripts are passed these parameters:
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

user_name="admin"
option="ignore_lockout_failure_attempts"
option_value="true"

source /etc/platform/openrc

# This will log to /var/log/platform.log
function log {
    logger -p local1.info $1
}

log "$NAME: Setting ${option} option for $user_name to exempt it from fail auth lockout."

if [ "$TO_RELEASE" == "20.06" ] && [ "$ACTION" == "activate" ]; then
    token=$(openstack token issue -c id -f value)
    if [ $? -ne 0 ]; then
        log "$NAME: Get admin token failed."
        exit 1
    fi

    user_id=$(openstack user show ${user_name} -c id -f value)
    if [ $? -ne 0 ]; then
        log "$NAME: Get user id for user ${user_name} failed."
        exit 1
    fi

    req_url="${OS_AUTH_URL}/users/${user_id}"
    data_json="{\"user\": {\"options\": {\"${option}\": ${option_value}}}}"

    ret=$(/usr/bin/curl -X PATCH -H "X-Auth-Token: ${token}" \
            -H "Content-Type: application/json" -d "${data_json}" "${req_url}")
    if [ $? -ne 0 ]; then
        log "$NAME: Set ${option} option for user ${user_name} failed."
        exit 1
    fi
    if echo ${ret} | grep '"error"'; then
        log "$NAME: Set ${option} option for user ${user_name} failed: ${ret}"
        exit 1
    fi
fi

exit 0

