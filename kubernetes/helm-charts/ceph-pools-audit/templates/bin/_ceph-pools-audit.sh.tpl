#!/bin/bash

{{/*
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
*/}}

ceph -s
ret=$?
if [ $ret -ne 0 ]; then
  msg="Error: Ceph cluster is not accessible, check Pod logs for details."
  echo "$msg"
  exit $ret
fi

touch /etc/ceph/ceph.client.admin.keyring

echo "RBD_POOL_CRUSH_RULESET: $RBD_POOL_CRUSH_RULESET"
if [ -z $RBD_POOL_CRUSH_RULESET ]; then
    msg="No Ceph crush ruleset specified"
    echo "$msg"
    exit 1
fi

ruleset=$(ceph osd crush rule dump $RBD_POOL_CRUSH_RULESET | grep \"ruleset\" | awk '{print $2}' | grep -Eo '[0-9]+')
ret=$?
if [ $ret -ne 0 ]; then
    msg="Ceph crush ruleset $RBD_POOL_CRUSH_RULESET not found, exit"
    echo "$msg"
    exit $ret
fi
echo "ruleset: $ruleset"

set -ex

POOLS=( $(ceph osd pool ls) )

for pool_name in "${POOLS[@]}"
do
    echo "Check for pool name: $pool_name"

    pool_crush_ruleset=$(ceph osd pool get $pool_name crush_ruleset | awk '{print $2}')
    echo "pool_crush_ruleset: $pool_crush_ruleset"
    if [ "$pool_crush_ruleset" != "$ruleset" ]; then
        continue
    fi

    pool_size=$(ceph osd pool get $pool_name size | awk '{print $2}')
    pool_min_size=$(ceph osd pool get $pool_name min_size | awk '{print $2}')

    echo "===> pool_size: $pool_size pool_min_size: $pool_min_size"
    if [ $pool_size != $RBD_POOL_REPLICATION ]; then
         echo "set replication for pool $pool_name at $RBD_POOL_REPLICATION"
         ceph osd pool set $pool_name size $RBD_POOL_REPLICATION
    fi

    if [ $pool_min_size != $RBD_POOL_MIN_REPLICATION ]; then
        echo "set min replication for pool $pool_name at $RBD_POOL_MIN_REPLICATION"
        ceph osd pool set $pool_name min_size $RBD_POOL_MIN_REPLICATION
    fi
done
