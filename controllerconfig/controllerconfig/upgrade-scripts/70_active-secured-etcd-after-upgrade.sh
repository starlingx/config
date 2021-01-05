#!/bin/bash

#
# Copyright (c) 2020 Intel Corporation.
#
# SPDX-License-Identifier: Apache-2.0
#
# Active secured etcd after upgrade.
#
# Note: this can be removed in the release after STX5.0

. /etc/platform/platform.conf

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
        echo ${HOST_IP}
        return
    fi

    # Try the DNS query
    # Because dnsmasq can resolve both a hostname to both an IPv4 and an IPv6
    # address in certain situations, and the last address is the IPv6, which
    # would be the management, this is preferred over the IPv4 pxeboot address,
    # so take the last address only.
    HOST_IP=$(dig +short ANY $host|tail -1)
    if [[ "${HOST_IP}" =~ ^[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$ ]]; then
        echo ${HOST_IP}
        return
    fi
    if [[ "${HOST_IP}" =~ ^[0-9a-z]*\:[0-9a-z\:]*$ ]]; then
        echo ${HOST_IP}
        return
    fi
}

enable_secured_etcd()
{
    STATIC_YAML="/opt/platform/puppet/${sw_version}/hieradata/static.yaml"
    SYSTEM_YAML="/opt/platform/puppet/${sw_version}/hieradata/system.yaml"

    if [[ ! -f ${STATIC_YAML} ]] || [[ ! -f ${SYSTEM_YAML} ]]; then
        echo "Could not find specific static/system yaml files in "\
             "/opt/platform/puppet/${sw_version}/hieradata!"
        exit 1
    fi

    ETCD_SEC_ENABLED=$(grep "platform::etcd::params::security_enabled" ${STATIC_YAML} | awk '{print $2}')
    CLUSTER_HOST_ADDRESS=$(grep "platform::network::cluster_host::params::subnet_start" ${SYSTEM_YAML} | awk '{print $2}')
    CLUSTER_HOST_ADDRESS_VERSION=$(grep "platform::network::cluster_host::params::subnet_version" ${SYSTEM_YAML} | awk '{print $2}')
    HOST_ADDR=$(get_ip $(hostname))

    if [ "$ETCD_SEC_ENABLED" != "true" ]; then
        ansible-playbook /usr/share/ansible/stx-ansible/playbooks/enable_secured_etcd.yml \
            -e "default_cluster_host_start_address=${CLUSTER_HOST_ADDRESS}" \
            -e "etcd_listen_address_version=${CLUSTER_HOST_ADDRESS_VERSION}" \
            -e "puppet_permdir=/opt/platform/puppet/${sw_version}" \
            -e "config_permdir=/opt/platform/config/${sw_version}" \
            -e "ipaddress=${HOST_ADDR}" \
            -e "k8s_root_ca_cert=''" \
            -e "k8s_root_ca_key=''"
        if [ $? -ne 0 ]; then
            echo "Failed to run ansible playbook!"
            exit 1
        fi
    fi
}

echo "${0} invoked with from_release = ${FROM_REL} to_release = ${TO_REL} action = ${ACTION}"

if [ ${FROM_REL} == "20.06" -a ${ACTION} == "activate" ]; then
    enable_secured_etcd
else
    echo "Only execute this upgrade code when the activate action is being done and the from release is 20.06!"
fi

exit 0
