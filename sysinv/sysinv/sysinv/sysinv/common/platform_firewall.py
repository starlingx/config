#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants

OAM_COMMON = {
    "tcp":
        {
            constants.PLATFORM_FIREWALL_SSH_PORT,
            constants.PLATFORM_FIREWALL_KUBE_APISERVER_PORT,
            constants.PLATFORM_NFV_PARAMS_API_PORT,
            constants.PLATFORM_PATCHING_PARAMS_PUBLIC_PORT,
            constants.PLATFORM_USM_PARAMS_PUBLIC_PORT,
            constants.PLATFORM_SYSINV_PARAMS_API_PORT,
            constants.PLATFORM_SMAPI_PARAMS_PORT,
            constants.PLATFORM_DOCKER_PARAMS_REGISTRY_PORT,
            constants.PLATFORM_DOCKER_PARAMS_TOKEN_PORT,
            constants.OPENSTACK_BARBICAN_PARAMS_API_PORT,
            constants.OPENSTACK_KEYSTONE_PARAMS_API_PORT,
            constants.PLATFORM_FM_PARAMS_API_PORT,
        },
    "udp":
        {
            constants.PLATFORM_FIREWALL_SM_PORT_1,
            constants.PLATFORM_FIREWALL_SM_PORT_2,
            constants.PLATFORM_FIREWALL_NTP_PORT,
            constants.PLATFORM_FIREWALL_PTP_PORT_1,
            constants.PLATFORM_FIREWALL_PTP_PORT_2,
        }
}

OAM_DC = {
    "tcp":
        {
            constants.PLATFORM_DCMANAGER_PARAMS_API_PORT,
            constants.PLATFORM_DCORCH_PARAMS_SYSINV_API_PROXY_PORT,
            constants.PLATFORM_DCORCH_PARAMS_PATCH_API_PROXY_PORT,
            constants.PLATFORM_DCORCH_PARAMS_USM_API_PROXY_PORT,
            constants.PLATFORM_DCORCH_PARAMS_IDENTITY_API_PROXY_PORT
        }
}


# list of ports to be open in the system controller side
SYSTEMCONTROLLER = \
    {"tcp":
        {
            constants.PLATFORM_FIREWALL_SSH_PORT: "ssh",
            389: "openLDAP",
            636: "openLDAP",
            4546: "stx-nfv",
            5001: "keystone-api",
            5492: "patching-api",
            5498: "usm-api",
            6386: "sysinv-api",
            constants.PLATFORM_FIREWALL_KUBE_APISERVER_PORT: "K8s API server",
            8220: "dcdbsync-api",
            constants.PLATFORM_DOCKER_PARAMS_REGISTRY_PORT: "Docker registry",
            constants.PLATFORM_DOCKER_PARAMS_TOKEN_PORT: "Registry token server",
            9312: "barbican-api",
            18003: "stx-fault",
            31001: "Elastic Dashboard and API",
            31090: "Kafka Brokers (NodePort)",
            31091: "Kafka Brokers (NodePort)",
            31092: "Kafka Brokers (NodePort)",
            31093: "Kafka Brokers (NodePort)",
            31094: "Kafka Brokers (NodePort)",
            31095: "Kafka Brokers (NodePort)",
            31096: "Kafka Brokers (NodePort)",
            31097: "Kafka Brokers (NodePort)",
            31098: "Kafka Brokers (NodePort)",
            31099: "Kafka Brokers (NodePort)"
        },
     "udp":
        {
            162: "snmp trap"
        }}

# list of ports to be open in the subcloud side
SUBCLOUD = \
    {"tcp":
        {
            constants.PLATFORM_FIREWALL_SSH_PORT: "ssh",
            4546: "stx-nfv",
            5001: "keystone-api",
            5492: "patching-api",
            5498: "usm-api",
            6386: "sysinv-api",
            8220: "dcdbsync-api",
            8326: "dcagent-api",
            constants.PLATFORM_DOCKER_PARAMS_REGISTRY_PORT: "Docker registry",
            constants.PLATFORM_DOCKER_PARAMS_TOKEN_PORT: "Registry token server",
            9312: "barbican-api",
            18003: "stx-fault",
            31001: "Elastic Dashboard and API"
        },
     "udp":
        {
            162: "snmp trap"
        }}

# If the variable needs to be present on puppet, add here to be included in system.yaml
# is also used to export to bootstrap's runtime.yaml
SYSTEM_CONFIG = {
    "platform::nfv::params::api_port":
        constants.PLATFORM_NFV_PARAMS_API_PORT,
    "platform::patching::params::public_port":
        constants.PLATFORM_PATCHING_PARAMS_PUBLIC_PORT,
    "platform::usm::params::public_port":
        constants.PLATFORM_USM_PARAMS_PUBLIC_PORT,
    "platform::sysinv::params::api_port":
        constants.PLATFORM_SYSINV_PARAMS_API_PORT,
    "platform::docker::params::registry_port":
        constants.PLATFORM_DOCKER_PARAMS_REGISTRY_PORT,
    "platform::docker::params::token_port":
        constants.PLATFORM_DOCKER_PARAMS_TOKEN_PORT,
    "platform::ceph::params::rgw_port":
        constants.PLATFORM_CEPH_PARAMS_RGW_PORT,
    "openstack::barbican::params::api_port":
        constants.OPENSTACK_BARBICAN_PARAMS_API_PORT,
    "openstack::keystone::params::api_port":
        constants.OPENSTACK_KEYSTONE_PARAMS_API_PORT,
    "platform::fm::params::api_port":
        constants.PLATFORM_FM_PARAMS_API_PORT,
    "platform::dcmanager::params::api_port":
        constants.PLATFORM_DCMANAGER_PARAMS_API_PORT,
    "platform::dcorch::params::sysinv_api_proxy_port":
        constants.PLATFORM_DCORCH_PARAMS_SYSINV_API_PROXY_PORT,
    "platform::dcorch::params::patch_api_proxy_port":
        constants.PLATFORM_DCORCH_PARAMS_PATCH_API_PROXY_PORT,
    "platform::dcorch::params::usm_api_proxy_port":
        constants.PLATFORM_DCORCH_PARAMS_USM_API_PROXY_PORT,
    "platform::dcorch::params::identity_api_proxy_port":
        constants.PLATFORM_DCORCH_PARAMS_IDENTITY_API_PROXY_PORT
}
