#!/bin/bash
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will update subcloud_status table in dcmanager database
# in preparation for upgrade to release 20.06.
#
# Subcloud load audit, introduced in release 20.06, entails creating
# load status record when a subcloud is added to the database and
# having the subcloud load status updated by dcmanager audit task.
# The script adds a load status record for each of the existing
# subclouds to ensure successful startup and operation of dcmanager
# when the system controller hosts are upgraded to 20.06.
#
# This script can be removed in the release that follows 20.06.
#

NAME=$(basename $0)

# The migration scripts are passed these parameters:
FROM_RELEASE=$1
TO_RELEASE=$2
ACTION=$3

# This will log to /var/log/platform.log
function log {
    logger -p local1.info $1
}

function create_configmap {
    cat > /etc/kubernetes/coredns.yaml <<EOF
# Based on https://github.com/kubernetes/kubernetes/blob/master/cluster/addons/dns/coredns/coredns.yaml.sed#L54-L82
# Hardcode dns_domain to cluster.local.
# Change policy from default of random to sequential, in order to attempt to
# resolve domain names with dnsmasq first.
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns
  namespace: kube-system
  labels:
      addonmanager.kubernetes.io/mode: EnsureExists
data:
  Corefile: |
    .:53 {
        errors
        health {
            lameduck 5s
        }
        ready
        kubernetes cluster.local in-addr.arpa ip6.arpa {
            pods insecure
            fallthrough in-addr.arpa ip6.arpa
            ttl 30
        }
        prometheus :9153
        forward . /etc/resolv.conf {
            policy sequential
        }
        cache 30
        loop
        reload
        loadbalance
    }
EOF

}

function apply_configmap {
    kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f /etc/kubernetes/coredns.yaml
    ret=$?
    return $ret
}


if [ "$TO_RELEASE" == "20.06" ] && [ "$ACTION" == "activate" ]; then
    log "$NAME: Migrating FROM release $FROM_RELEASE"
    create_configmap
    apply_configmap
    ret=$?
    if [ $ret -ne 0 ]; then
        log "$NAME: Applying CoreDNS ConfigMap failed"
        exit 1
    fi

fi

exit 0
