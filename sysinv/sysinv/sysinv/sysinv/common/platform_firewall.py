#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants

# Port definitions in this file are augmented with a comma separated list of
# additional information as a comment. These are parsed to generate user
# documentation.
#
# Updates must be made for changes and additions:
#
# (<Desc>), <Context>, <Network>, <Endpoints>, <Hosts>, <Note>, <HTTPS>, <_stX>, <_pl>, <_os>, <_an>
#
# (<Desc>)    - Short description such as 'SSH'. Only needed on ports that do
#               not assign a value.
# <Context>   - Platform, OpenStack or Analytics
# <Network>   - oam or mgmt
# <Endpoints> - Bidirectional, System Controller -> Subclouds, Subclouds ->
#               System Controller, Not used
# <Hosts>     - Where the port can be opened (system controller, subcloud)
# <Note>      - Any additional notes
# <HTTPS>     - 'Yes' if HTTPS is enabled
#
# <_stX>, <_pl>, <_os> and <_an> - Non printing control values defining where
# the port documentation should be published:
#   - _stx=StarlingX
#   - _pl=Platform
#   - _os=OpenStack
#   - _an=Analytics

# OAM_COMMON documentation fields format:
# <Desc>, <Context>, <Network>, <Endpoints>, <Hosts>, <Note>, <HTTPS>, <_stX>, <_pl>, <_os>, <_an>
# (Network can be empty - defaults to 'oam')
OAM_COMMON = {
    "tcp":
        {
            constants.PLATFORM_FIREWALL_SSH_PORT,  # noqa: E501 docu: SSH, platform,,Bidirectional,Allowed on system controller and subclouds.,For admin login.,,y,y,n,n
            constants.PLATFORM_FIREWALL_KUBE_APISERVER_PORT,  # noqa: E501 docu: Kube API server,platform,,Not used,Allowed on system controller and subclouds.,,Yes,y,y,n,n
            constants.PLATFORM_NFV_PARAMS_API_PORT,  # noqa: E501 docu: NFV, platform,,Not used,Allowed (service public endpoint) on system controller and subclouds.,vim-restapi public endpoint.,,y,y,n,n
            constants.PLATFORM_PATCHING_PARAMS_PUBLIC_PORT,  # noqa: E501 docu: Patching, platform,,Allowed (service public endpoint) on both,Not used between System Controller and Subclouds,patching-api public endpoint,,y,y,n,n
            constants.PLATFORM_USM_PARAMS_PUBLIC_PORT,  # noqa: E501 docu: USM, platform,oam,Allowed (service public endpoint) on both,Not used between System Controller and Subclouds,Unified Software Management API,Yes,y,y,n,n
            constants.PLATFORM_SYSINV_PARAMS_API_PORT,  # noqa: E501 docu: Sys Inv, platform,,Not used between system controller and Subclouds.,Allowed (service public endpoint) on controllers and subclouds.,,,y,y,n,n
            constants.PLATFORM_SMAPI_PARAMS_PORT,  # noqa: E501 docu: SM API, platform,,Not used between system controller and Subclouds.,Allowed (service public endpoint) on controllers and subclouds.,sm-api public endpoint.,,y,y,n,n
            constants.PLATFORM_DOCKER_PARAMS_REGISTRY_PORT,  # noqa: E501 docu: Docker, platform,,Bidirectional,Allowed (service public endpoint) on controllers and subclouds.,,Yes,y,y,n,n
            constants.PLATFORM_DOCKER_PARAMS_TOKEN_PORT,  # noqa: E501 docu: Docker, platform,,Bidirectional,Allowed (service public endpoint) on controllers and subclouds.,,Yes,y,y,n,n
            constants.OPENSTACK_BARBICAN_PARAMS_API_PORT,  # noqa: E501 docu: Barbican, platform,,Not used,Allowed (service public endpoint) on controllers and subclouds.,,,y,n,y,n
            constants.OPENSTACK_KEYSTONE_PARAMS_API_PORT,  # noqa: E501 docu: Keystone, platform,,Not used,Allowed (service public endpoint) on controllers and subclouds.,,,y,n,y,n
            constants.PLATFORM_FM_PARAMS_API_PORT,  # noqa: E501 docu: Fault Management, platform,,Not used,Allowed (service public endpoint) on controllers and subclouds.,,,y,y,n,n
            constants.PLATFORM_FIREWALL_HTTP_PORT,  # noqa: E501 docu: Web access, platform,,Not used,Allowed (service public endpoint) on controllers and subclouds.,,,y,y,n,n
            constants.PLATFORM_CEPH_PARAMS_RGW_PORT,  # noqa: E501 docu: CEPH parameters, platform,,Not used,Allowed (service public endpoint) on controllers and subclouds.,,,y,y,n,n
        },
    "udp":
        {
            constants.PLATFORM_FIREWALL_SM_PORT_1,  # noqa: E501 docu: SM, platform,,Not used,Allowed on controllers and subclouds.,,,y,y,n,n
            constants.PLATFORM_FIREWALL_SM_PORT_2,  # noqa: E501 docu: SM, platform,,Not used,Allowed on controllers and subclouds.,,,y,y,n,n
            constants.PLATFORM_FIREWALL_NTP_PORT,  # noqa: E501 docu: NTP, platform,,Not used,Allowed on controllers and subclouds.,,,y,y,n,n
            constants.PLATFORM_FIREWALL_PTP_PORT_1,  # noqa: E501 docu: PTP, platform,oam,Not used,Allowed on controllers and subclouds.,precision time protocol (PTP) port,,y,y,n,n
            constants.PLATFORM_FIREWALL_PTP_PORT_2,  # noqa: E501 docu: PTP, platform,oam,Not used,Allowed on controllers and subclouds.,precision time protocol (PTP) port,,y,y,n,n
        }
}

# OAM_DC documentation fields format:
# <Desc>, <Context>, <Network>, <Endpoints>, <Hosts>, <Note>, <HTTPS>, <_stX>, <_pl>, <_os>, <_an>
# (Network can be empty - defaults to 'oam')
OAM_DC = {
    "tcp":
        {
            constants.PLATFORM_DCMANAGER_PARAMS_API_PORT,  # noqa: E501 docu: DC Manager Params API,platform,oam,Not used,Allowed (service public endpoint) on system controller and subclouds.,,,y,y,n,n
            constants.PLATFORM_DCORCH_PARAMS_SYSINV_API_PROXY_PORT,  # noqa: E501 docu: DC Orchestration sys-inv params API,platform,oam,Allowed (service public endpoint) on system controller,Allowed (service public endpoint) on system controller,DC Orchestration params patch API,,y,y,n,n
            constants.PLATFORM_DCORCH_PARAMS_PATCH_API_PROXY_PORT,  # noqa: E501 docu: DC Orchestration params patch API, platform,oam,Not used,Allowed (service public endpoint) on system controller.,corch-patch-api-proxy public endpoint.,,y,y,n,n
            constants.PLATFORM_DCORCH_PARAMS_USM_API_PROXY_PORT,  # noqa: E501 docu: DC Orchestration USM params API,platform,oam,Allowed (service public endpoint) on system controller,Allowed (service public endpoint) on system controller,DC Orchestration USM params API,,y,y,n,n
            constants.PLATFORM_DCORCH_PARAMS_IDENTITY_API_PROXY_PORT  # noqa: E501 docu: DC Orchestration Identity params API,platform,oam,Allowed (service public endpoint) on system controller,Allowed (service public endpoint) on system controller,DC Orchestration Identity params API,,y,y,n,n
        }
}

# list of ports to be open in the system controller side

# SYSTEMCONTROLLER documentation fields format:
# <Context>, <Network>, <Endpoints>, <Hosts>, <Note>, <HTTPS>, <_stX>, <_pl>, <_os>, <_an>
SYSTEMCONTROLLER = \
    {"tcp":
        {
            constants.PLATFORM_FIREWALL_SSH_PORT: "ssh",  # noqa: E501 docu: platform,mgmt,Allowed for terminal shell access ,Allowed for terminal shell access ,Patching API,,y,y,n,n
            389: "openLDAP",  # noqa: E501 docu: platform,mgmt,Subclouds -> System Controller,Allowed on system controller and subclouds. NA on subclpuds.,LDAP service,,y,y,n,n
            636: "openLDAP",  # noqa: E501 docu: platform,mgmt,User management. Not used between system controller and Subclouds,Blocked (by gnp) on controllers. NA on subclpuds.,,,y,y,n,n
            4546: "stx-nfv",  # noqa: E501 docu: platform,mgmt,Bidirectional,Keystone API.Allowed (service public endpoint) on controllers and subclouds.,vim-restapi admin endpoint.,Yes,y,y,n,n
            5001: "keystone-api",  # noqa: E501 docu: platform,mgmt,Bidirectional,Allowed (service public endpoint) on controllers and subclouds.,,Yes,y,y,n,n
            5492: "patching-api",  # noqa: E501 docu: platform,mgmt,Bidirectional,Allowed (service public endpoint) on controllers and subclouds.,Patching API admin endpoint.,Yes,y,y,n,n
            5498: "usm-api",  # noqa: E501 docu: platform,mgmt,Bidirectional,Allowed (service public endpoint) on controllers and subclouds.,Unified Sofware Management API endpoint,Yes,y,y,n,n
            6386: "sysinv-api",  # noqa: E501 docu: platform,mgmt,Bidirectional,Allowed (service public endpoint) on controllers and subclouds.,,Yes,y,y,n,n
            constants.PLATFORM_FIREWALL_KUBE_APISERVER_PORT: "K8s API server",  # noqa: E501 docu: platform,mgmt,Not used between system controller and Subclouds.,Allowed (service public endpoint) on controllers and subclouds.,,Yes,y,y,n,n
            8220: "dcdbsync-api",  # noqa: E501 docu: platform,mgmt,Bidirectional,Allowed (service public endpoint) on controllers and subclouds. Allowed on controllers and subclouds.,,Yes,y,y,n,n
            constants.PLATFORM_DOCKER_PARAMS_REGISTRY_PORT: "Docker registry",  # noqa: E501 docu: platform,mgmt,Bidirectional,Allowed (serving port) on system controller and subcloud,,Yes,y,y,n,n
            constants.PLATFORM_DOCKER_PARAMS_TOKEN_PORT: "Registry token server",  # noqa: E501 docu: platform,mgmt,Bidirectional,Allowed (serving port) on system controller and subcloud,,Yes,y,y,n,n
            9312: "barbican-api",  # noqa: E501 docu: platform,mgmt,Bidirectional,Allowed on system controller and subclouds (service admin endpoint).,,Yes,y,y,n,n
            18003: "stx-fault",  # noqa: E501 docu: platform,mgmt,Bidirectional,Allowed on system controller and subclouds (service admin endpoint).,,Yes,y,y,n,n
            31001: "Elastic Dashboard and API",  # noqa: E501 docu: analytics,mgmt,Bidirectional,Allowed on system controller (NodePort).,Only used when Analytics is applied,Yes,n,y,n,y
            31090: "Kafka Brokers (NodePort)",  # noqa: E501 docu: analytics,mgmt,Bidirectional,Allowed on system controller (NodePort).,Only used when Analytics is applied.,Yes,n,y,n,y
            31091: "Kafka Brokers (NodePort)",  # noqa: E501 docu: analytics,mgmt,Bidirectional,Allowed on system controller (NodePort).,Only used when Analytics is applied.,Yes,n,y,n,y
            31092: "Kafka Brokers (NodePort)",  # noqa: E501 docu: analytics,mgmt,Bidirectional,Allowed on system controller (NodePort).,Only used when Analytics is applied.,Yes,n,y,n,y
            31093: "Kafka Brokers (NodePort)",  # noqa: E501 docu: analytics,mgmt,Bidirectional,Allowed on system controller (NodePort).,Only used when Analytics is applied.,Yes,n,y,n,y
            31094: "Kafka Brokers (NodePort)",  # noqa: E501 docu: analytics,mgmt,Bidirectional,Allowed on system controller (NodePort).,Only used when Analytics is applied.,Yes,n,y,n,y
            31095: "Kafka Brokers (NodePort)",  # noqa: E501 docu: analytics,mgmt,Bidirectional,Allowed on system controller (NodePort).,Only used when Analytics is applied.,Yes,n,y,n,y
            31096: "Kafka Brokers (NodePort)",  # noqa: E501 docu: analytics,mgmt,Bidirectional,Allowed on system controller (NodePort).,Only used when Analytics is applied.,Yes,n,y,n,y
            31097: "Kafka Brokers (NodePort)",  # noqa: E501 docu: analytics,mgmt,Bidirectional,Allowed on system controller (NodePort).,Only used when Analytics is applied.,Yes,n,y,n,y
            31098: "Kafka Brokers (NodePort)",  # noqa: E501 docu: analytics,mgmt,Bidirectional,Allowed on system controller (NodePort).,Only used when Analytics is applied.,Yes,n,y,n,y
            31099: "Kafka Brokers (NodePort)"  # noqa: E501 docu: analytics,mgmt,Bidirectional,Allowed on system controller (NodePort).,Only used when Analytics is applied.,Yes,n,y,n,y
        },
     "udp":
        {
            162: "snmp trap"  # noqa: E501 docu: platform,mgmt,Bidirectional,Allowed on system controllers and subclouds.,,,y,y,n,n
        }}

# list of ports to be open in the subcloud side

# SUBCLOUD documentation fields format:
# <Context>, <Network>, <Endpoints>, <Hosts>, <Note>, <HTTPS>, <_stX>, <_pl>, <_os>, <_an>
SUBCLOUD = \
    {"tcp":
        {
            constants.PLATFORM_FIREWALL_SSH_PORT: "ssh",  # noqa: E501 docu: platform,mgmt or admin,Bidirectional,Andre?,For admin login.,,y,y,n,n
            4546: "stx-nfv",  # noqa: E501 docu: platform,mgmt or admin,Not used,vim-restapi. public endpoint. Allowed (service public endpoint) on controllers and subclouds.,,,y,y,n,n
            5001: "keystone-api",  # noqa: E501 docu: platform,mgmt or admin,Not used,Allowed (service public endpoint) on controllers and subclouds.,,,y,y,y,n
            5492: "patching-api",  # noqa: E501 docu: platform,mgmt or admin,Bidirectional,Allowed (service public endpoint) on controllers and subclouds.,Patching API admin endpoint.,Yes,y,y,n,n
            5498: "usm-api",  # noqa: E501 docu: platform,mgmt or admin,Bidirectional,Allowed (service public endpoint) on controllers and subclouds.,Unified Software Management API endpoint,Yes,y,y,n,n
            6386: "sysinv-api",  # noqa: E501 docu: platform,mgmt or admin,Bidirectional,Allowed (service admin endpoint) on system controller and subclouds.,,Yes,y,y,n,n
            8220: "dcdbsync-api",  # noqa: E501 docu: platform,mgmt or admin,Bidirectional,Allowed (service admin endpoint) on system controller and subclouds.,,Yes,y,y,n,n
            8326: "dcagent-api",  # noqa: E501 docu: platform,mgmt or admin,Bidirectional,Allowed (service admin endpoint) on system controller and subclouds.,,Yes,y,y,n,n
            constants.PLATFORM_DOCKER_PARAMS_REGISTRY_PORT: "Docker registry",  # noqa: E501 docu: platform,mgmt or admin,Bidirectional,Allowed (serving port) on system controller and subclouds.,,Yes,y,y,n,n
            constants.PLATFORM_DOCKER_PARAMS_TOKEN_PORT: "Registry token server",  # noqa: E501 docu: platform,mgmt or admin,Bidirectional,Allowed (serving port) on system controller and subclouds.,,Yes,y,y,n,n
            9312: "barbican-api",  # noqa: E501 docu: platform,mgmt or admin,Bidirectional,Allowed (service admin endpoint) on system controller and subclouds.,,Yes,y,y,y,n
            18003: "stx-fault",  # noqa: E501 docu: platform,mgmt or admin,Bidirectional,Allowed (service admin endpoint) on system controller and subclouds.,,Yes,y,y,n,n
            31001: "Elastic Dashboard and API"  # noqa: E501 docu: analytics,mgmt or admin,Bidirectional,Allowed (nodePort) on system controller.,Only used when Analytics is applied.,Yes,n,y,n,y
        },
     "udp":
        {
            162: "snmp trap"  # noqa: E501 docu: platform,mgmt or admin,Bidirectional,Allowed on system controllers and subclouds.,,,y,y,n,n
        }}


# If the variable needs to be present on puppet, add here to be included in system.yaml
# is also used to export to bootstrap's runtime.yaml

# SYSTEM_CONFIG documentation fields format:
# <Desc>, <Context>, <Network>, <Endpoints>, <Hosts>, <Note>, <HTTPS>, <_stX>, <_pl>, <_os>, <_an>
SYSTEM_CONFIG = {
    "platform::nfv::params::api_port":
        constants.PLATFORM_NFV_PARAMS_API_PORT,  # noqa: E501 docu: NFV Params API, platform,oam,Not used,Allowed (service public endpoint) on system controller.,vim-restapi public endpoint.,,n,n,n,n
    "platform::patching::params::public_port":
        constants.PLATFORM_PATCHING_PARAMS_PUBLIC_PORT,  # noqa: E501 docu: Patching Params API, platform,oam,Not used,Allowed (service public endpoint) on system controller and subclouds.,patching-api public endpoint.,,n,n,n,n
    "platform::usm::params::public_port":
        constants.PLATFORM_USM_PARAMS_PUBLIC_PORT,  # noqa: E501 docu: USM Params API, platform,Andre?,Andre?,Anfre?,<Andre - pls add note>,Andre?,n,n,n,n
    "platform::sysinv::params::api_port":
        constants.PLATFORM_SYSINV_PARAMS_API_PORT,  # noqa: E501 docu: Sys-Inv Params API,platform,oam,Not used,Allowed (service public endpoint) on system controller and subclouds.,,,n,n,n,n
    "platform::docker::params::registry_port":
        constants.PLATFORM_DOCKER_PARAMS_REGISTRY_PORT,  # noqa: E501 docu: Docker parameters registry,platform,oam,Not used,Allowed (service public endpoint) on system controller and subclouds.,,Yes,n,n,n,n
    "platform::docker::params::token_port":
        constants.PLATFORM_DOCKER_PARAMS_TOKEN_PORT,  # noqa: E501 docu: Docker parameter token,platform,oam,Not used,Allowed (service public endpoint) on system controller and subclouds.,,Yes,n,n,n,n
    "platform::ceph::params::rgw_port":
        constants.PLATFORM_CEPH_PARAMS_RGW_PORT,  # noqa: E501 docu: CEPH parameters, platform,,Not used,Allowed (service public endpoint) on controllers and subclouds.,,,y,y,n,n
    "openstack::barbican::params::api_port":
        constants.OPENSTACK_BARBICAN_PARAMS_API_PORT,  # noqa: E501 docu: Barbican parameters API,platform,oam,Not used,Allowed (service public endpoint) on system controller and subclouds.,,,n,n,n,n
    "openstack::keystone::params::api_port":
        constants.OPENSTACK_KEYSTONE_PARAMS_API_PORT,  # noqa: E501 docu: Keystone Params API,platform,oam,Not used,Allowed (service public endpoint) on system controller and subclouds.,,,n,n,n,n
    "platform::fm::params::api_port":
        constants.PLATFORM_FM_PARAMS_API_PORT,  # noqa: E501 docu: Fault Management Params API,platform,oam,Not used,Allowed (service public endpoint) on system controller and subclouds.,,,n,n,n,n
    "platform::dcmanager::params::api_port":
        constants.PLATFORM_DCMANAGER_PARAMS_API_PORT,  # noqa: E501 docu: DC Manager Params API,platform,oam,Not used,Allowed (service public endpoint) on system controller and subclouds.,,,n,n,n,n
    "platform::dcorch::params::sysinv_api_proxy_port":
        constants.PLATFORM_DCORCH_PARAMS_SYSINV_API_PROXY_PORT,  # noqa: E501 docu: DC Orchestration sys-inv params API,platform,Andre?,Andre?,Andre?,<Andre - please add note>,Andre?,n,n,n,n
    "platform::dcorch::params::patch_api_proxy_port":
        constants.PLATFORM_DCORCH_PARAMS_PATCH_API_PROXY_PORT,  # noqa: E501 docu: DC Orchestration params patch API,platform,oam,Not used,Allowed (service public endpoint) on system controller.,dcorch-patch-api-proxy public endpoint.,,n,n,n,n
    "platform::dcorch::params::usm_api_proxy_port":
        constants.PLATFORM_DCORCH_PARAMS_USM_API_PROXY_PORT,  # noqa: E501 docu: DC Orchestration USM params API,platform,Andre?,Andre?,Andre?,<Andre - please add note>,Andre?,n,n,n,n
    "platform::dcorch::params::identity_api_proxy_port":
        constants.PLATFORM_DCORCH_PARAMS_IDENTITY_API_PROXY_PORT  # noqa: E501 docu: DC Orchestration Identity params API,platform,Andre?,Andre?,Andre?,<Andre - please add note>,Andre?,n,n,n,n
}
