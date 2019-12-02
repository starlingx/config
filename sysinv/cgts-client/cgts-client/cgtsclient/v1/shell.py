#
# Copyright (c) 2013-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#

from cgtsclient.common import utils
from cgtsclient.v1 import address_pool_shell
from cgtsclient.v1 import address_shell
from cgtsclient.v1 import app_shell
from cgtsclient.v1 import ceph_mon_shell
from cgtsclient.v1 import certificate_shell
from cgtsclient.v1 import cluster_shell
from cgtsclient.v1 import controller_fs_shell
from cgtsclient.v1 import datanetwork_shell
from cgtsclient.v1 import drbdconfig_shell
from cgtsclient.v1 import ethernetport_shell
from cgtsclient.v1 import health_shell
from cgtsclient.v1 import helm_shell
from cgtsclient.v1 import host_fs_shell

from cgtsclient.v1 import icommunity_shell
from cgtsclient.v1 import icpu_shell
from cgtsclient.v1 import idisk_shell
from cgtsclient.v1 import idns_shell
from cgtsclient.v1 import iextoam_shell
from cgtsclient.v1 import iHost_shell
from cgtsclient.v1 import iinterface_shell
from cgtsclient.v1 import ilvg_shell
from cgtsclient.v1 import imemory_shell
from cgtsclient.v1 import interface_datanetwork_shell
from cgtsclient.v1 import interface_network_shell
from cgtsclient.v1 import intp_shell
from cgtsclient.v1 import iprofile_shell
from cgtsclient.v1 import ipv_shell
from cgtsclient.v1 import isensor_shell
from cgtsclient.v1 import isensorgroup_shell
from cgtsclient.v1 import istor_shell
from cgtsclient.v1 import isystem_shell
from cgtsclient.v1 import itrapdest_shell
from cgtsclient.v1 import iuser_shell

from cgtsclient.v1 import kube_upgrade_shell
from cgtsclient.v1 import kube_version_shell
from cgtsclient.v1 import label_shell
from cgtsclient.v1 import license_shell
from cgtsclient.v1 import lldp_agent_shell
from cgtsclient.v1 import lldp_neighbour_shell
from cgtsclient.v1 import load_shell
from cgtsclient.v1 import network_shell
from cgtsclient.v1 import partition_shell
from cgtsclient.v1 import pci_device_shell
from cgtsclient.v1 import port_shell
from cgtsclient.v1 import ptp_shell
from cgtsclient.v1 import registry_image_shell
from cgtsclient.v1 import remotelogging_shell
from cgtsclient.v1 import route_shell
from cgtsclient.v1 import sdn_controller_shell
from cgtsclient.v1 import service_parameter_shell
from cgtsclient.v1 import sm_service_nodes_shell
from cgtsclient.v1 import sm_service_shell
from cgtsclient.v1 import sm_servicegroup_shell
from cgtsclient.v1 import storage_backend_shell
from cgtsclient.v1 import storage_tier_shell
from cgtsclient.v1 import upgrade_shell


COMMAND_MODULES = [
    isystem_shell,
    iuser_shell,
    idns_shell,
    intp_shell,
    ptp_shell,
    iextoam_shell,
    controller_fs_shell,
    storage_backend_shell,
    ceph_mon_shell,
    drbdconfig_shell,
    iHost_shell,
    icpu_shell,
    imemory_shell,
    iinterface_shell,
    idisk_shell,
    istor_shell,
    ilvg_shell,
    ipv_shell,
    iprofile_shell,
    sm_service_nodes_shell,
    sm_servicegroup_shell,
    sm_service_shell,
    icommunity_shell,
    itrapdest_shell,
    ethernetport_shell,
    port_shell,
    address_shell,
    address_pool_shell,
    route_shell,
    isensor_shell,
    isensorgroup_shell,
    load_shell,
    pci_device_shell,
    upgrade_shell,
    network_shell,
    interface_network_shell,
    datanetwork_shell,
    interface_datanetwork_shell,
    service_parameter_shell,
    cluster_shell,
    lldp_agent_shell,
    lldp_neighbour_shell,
    health_shell,
    registry_image_shell,
    remotelogging_shell,
    sdn_controller_shell,
    partition_shell,
    license_shell,
    certificate_shell,
    storage_tier_shell,
    helm_shell,
    label_shell,
    app_shell,
    host_fs_shell,
    kube_version_shell,
    kube_upgrade_shell,
]


def enhance_parser(parser, subparsers, cmd_mapper):
    '''Take a basic (nonversioned) parser and enhance it with
    commands and options specific for this version of API.

    :param parser: top level parser :param subparsers: top level
        parser's subparsers collection where subcommands will go
    '''
    for command_module in COMMAND_MODULES:
        utils.define_commands_from_module(subparsers, command_module,
                                          cmd_mapper)
