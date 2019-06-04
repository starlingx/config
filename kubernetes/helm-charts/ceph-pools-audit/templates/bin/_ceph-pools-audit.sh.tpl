#!/bin/bash

{{/*
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
*/}}

ceph -s
if [ $? -ne 0 ]; then
    echo "Error: Ceph cluster is not accessible, check Pod logs for details."
    exit 1
fi

touch /etc/ceph/ceph.client.admin.keyring

echo "RBD_POOL_CRUSH_RULE_NAME: ${RBD_POOL_CRUSH_RULE_NAME}"
if [ -z "${RBD_POOL_CRUSH_RULE_NAME}" ]; then
    echo "Error: No Ceph crush rule name specified"
    exit 1
fi

ceph osd crush rule ls | grep -q "${RBD_POOL_CRUSH_RULE_NAME}"
if [ $? -ne 0 ]; then
    echo "Error: Ceph crush rule ${RBD_POOL_CRUSH_RULE_NAME} not found, exit"
    exit 1
fi

POOLS=( $(ceph osd pool ls) )

for pool in "${POOLS[@]}"; do
    echo "Check for pool name: $pool"

    pool_rule=$(ceph osd pool get $pool crush_rule | awk '{print $2}')
    echo "Pool crush rule name: ${pool_rule}"
    if [ "${pool_rule}" != "${RBD_POOL_CRUSH_RULE_NAME}" ]; then
        continue
    fi

    pool_size=$(ceph osd pool get $pool size | awk '{print $2}')
    pool_min_size=$(ceph osd pool get $pool min_size | awk '{print $2}')

    echo "===> pool_size: ${pool_size} pool_min_size: ${pool_min_size}"
    if [ "${pool_size}" != "${RBD_POOL_REPLICATION}" ]; then
        echo "Set size for $pool to ${RBD_POOL_REPLICATION}"
        ceph osd pool set $pool size "${RBD_POOL_REPLICATION}"
    fi

    if [ "${pool_min_size}" != "${RBD_POOL_MIN_REPLICATION}" ]; then
        echo "Set min_size for $pool to ${RBD_POOL_MIN_REPLICATION}"
        ceph osd pool set $pool min_size "${RBD_POOL_MIN_REPLICATION}"
    fi
done
