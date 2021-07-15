#!/bin/bash

#
# Copyright (c) 2021 Intel Corporation.
#
# SPDX-License-Identifier: Apache-2.0
#

# Enable separate etcd ca during upgrade.
#
# Note: this can be removed in the release after STX6.0

. /etc/platform/platform.conf

# This will log to /var/log/platform.log
function log {
    logger -p local1.info $1
}


FROM_REL=$1
TO_REL=$2
ACTION=$3

# below function is cloned from ../scripts/controller_config
get_ip()
{
    HOST_NAME=$1

    # Check /etc/hosts for the hostname
    HOST_IP=$(cat /etc/hosts | grep "${HOST_NAME}" | awk '{print $1}')
    if [ -n "${HOST_IP}" ]; then
        echo "${HOST_IP}"
        return
    fi

    # Try the DNS query
    # Because dnsmasq can resolve both a hostname to both an IPv4 and an IPv6
    # address in certain situations, and the last address is the IPv6, which
    # would be the management, this is preferred over the IPv4 pxeboot address,
    # so take the last address only.
    HOST_IP=$(dig +short ANY $host|tail -1)
    if [[ "${HOST_IP}" =~ ^[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$ ]]; then
        echo "${HOST_IP}"
        return
    fi
    if [[ "${HOST_IP}" =~ ^[0-9a-z]*\:[0-9a-z\:]*$ ]]; then
        echo "${HOST_IP}"
        return
    fi
}

enable_separate_etcd_ca()
{
    STATIC_YAML="/opt/platform/puppet/${sw_version}/hieradata/static.yaml"
    SYSTEM_YAML="/opt/platform/puppet/${sw_version}/hieradata/system.yaml"

    if [[ ! -f ${STATIC_YAML} ]] || [[ ! -f ${SYSTEM_YAML} ]]; then
        log "Could not find specific static/system yaml files in /opt/platform/puppet/${sw_version}/hieradata!"
        exit 1
    fi

    CLUSTER_FLOATING_ADDRESS=$(grep "platform::network::cluster_host::params::controller_address" ${SYSTEM_YAML} | awk '{print $2}')
    CLUSTER_FLOATING_ADDRESS_VERSION=$(grep "platform::network::cluster_host::params::subnet_version" ${SYSTEM_YAML} | awk '{print $2}')
    HOST_ADDR=$(get_ip $(hostname))

    ansible-playbook /usr/share/ansible/stx-ansible/playbooks/separate_etcd_ca.yml \
        -e "cluster_floating_address=${CLUSTER_FLOATING_ADDRESS}" \
        -e "etcd_listen_address_version=${CLUSTER_FLOATING_ADDRESS_VERSION}" \
        -e "puppet_permdir=/opt/platform/puppet/${sw_version}" \
        -e "config_permdir=/opt/platform/config/${sw_version}" \
        -e "ipaddress=${HOST_ADDR}" \
        -e "etcd_root_ca_cert=''" \
        -e "etcd_root_ca_key=''"
    if [ $? -ne 0 ]; then
        log "Failed to run ansible playbook!"
        exit 1
    fi
}

log "${0} invoked with from_release = ${FROM_REL} to_release = ${TO_REL} action = ${ACTION}"

if [ ${FROM_REL} == "21.05" -a ${ACTION} == "activate" ]; then
    enable_separate_etcd_ca
else
    log "Only execute this upgrade code when the activate action is being done and the from release is 21.05!"
fi

exit 0
