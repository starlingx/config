#!/bin/bash

# Copyright (c) 2022 Wind River Systems, Inc.

# SPDX-License-Identifier: Apache-2.0

# Remove Etcd RBAC against V2 backend
#
# Note: this can be removed in the release after STX7.0

. /etc/platform/platform.conf

# This will log to /var/log/platform.log
function log {
    logger -p local1.info $1
}

FROM_REL=$1
TO_REL=$2
ACTION=$3

ACCEPTED_REL="21.12"

STATIC="/opt/platform/puppet/${sw_version}/hieradata/static.yaml"
NET_KEY="platform::etcd::params::bind_address"
NETVER_KEY="platform::etcd::params::bind_address_version"

PORT="2379"
ETCD_CERT="/etc/etcd/etcd-client.crt"
ETCD_KEY="/etc/etcd/etcd-client.key"
ETCD_CA="/etc/etcd/ca.crt"
ETCD_CMDS="auth disable
user remove root
user remove apiserver-etcd-client"

remove-etcd-rbac()
{
    local host_addr
    local host_ver
    local server_url

    if [[ ! -f "${STATIC}" ]]; then
        log "Script $0 does not find static yaml file: $STATIC"
        exit 1
    fi

    host_addr="$( grep "^${NET_KEY}:" "${STATIC}" | gawk '{print $NF}' )"
    host_ver="$( grep "^${NETVER_KEY}:" "${STATIC}" | gawk '{print $NF}' )"

    if [ "$host_ver" == "6" ]; then
        server_url="https://[${host_addr}]:${PORT},https://127.0.0.1:${PORT}"
    else
        server_url="https://${host_addr}:${PORT},https://127.0.0.1:${PORT}"
    fi

    # Ignore the return code of etcdctl calls here because the
    # configuration against v2 API does not persist BnR; it may be absent
    while read -r cmd; do
        etcdctl --cert-file="${ETCD_CERT}" \
            --key-file="${ETCD_KEY}" \
            --ca-file="${ETCD_CA}" \
            --endpoint="${server_url}" \
            $cmd
    done <<<"$ETCD_CMDS"
}

log "Script ${0} invoked with from_release = ${FROM_REL} to_release = ${TO_REL} action = ${ACTION}"

if [ ${FROM_REL} == "$ACCEPTED_REL" -a ${ACTION} == "activate" ]; then
    remove-etcd-rbac
else
    log "Script $0: No actions required from release $FROM_REL to $TO_REL with action $ACTION"
fi

exit 0
