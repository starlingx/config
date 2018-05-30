# Copyright 2012 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#


from cgtsclient.common import http
from cgtsclient.v1 import address
from cgtsclient.v1 import address_pool
from cgtsclient.v1 import isystem
from cgtsclient.v1 import ihost
from cgtsclient.v1 import inode
from cgtsclient.v1 import icpu
from cgtsclient.v1 import imemory
from cgtsclient.v1 import iinterface
from cgtsclient.v1 import idisk
from cgtsclient.v1 import istor
from cgtsclient.v1 import ipv
from cgtsclient.v1 import ilvg
from cgtsclient.v1 import iuser
from cgtsclient.v1 import idns
from cgtsclient.v1 import intp
from cgtsclient.v1 import iextoam
from cgtsclient.v1 import controller_fs
from cgtsclient.v1 import storage_backend
from cgtsclient.v1 import storage_lvm
from cgtsclient.v1 import storage_file
from cgtsclient.v1 import storage_external
from cgtsclient.v1 import storage_ceph
from cgtsclient.v1 import ceph_mon
from cgtsclient.v1 import drbdconfig
from cgtsclient.v1 import iprofile
from cgtsclient.v1 import icommunity
from cgtsclient.v1 import itrapdest
from cgtsclient.v1 import ialarm
from cgtsclient.v1 import iinfra
from cgtsclient.v1 import port
from cgtsclient.v1 import ethernetport
from cgtsclient.v1 import route
from cgtsclient.v1 import event_log
from cgtsclient.v1 import event_suppression
from cgtsclient.v1 import isensor
from cgtsclient.v1 import isensorgroup
from cgtsclient.v1 import load
from cgtsclient.v1 import pci_device
from cgtsclient.v1 import upgrade
from cgtsclient.v1 import network
from cgtsclient.v1 import service_parameter
from cgtsclient.v1 import cluster
from cgtsclient.v1 import lldp_agent
from cgtsclient.v1 import lldp_neighbour
from cgtsclient.v1 import license
from cgtsclient.v1 import sm_service_nodes
from cgtsclient.v1 import sm_service
from cgtsclient.v1 import sm_servicegroup
from cgtsclient.v1 import health
from cgtsclient.v1 import remotelogging
from cgtsclient.v1 import sdn_controller
from cgtsclient.v1 import tpmconfig
from cgtsclient.v1 import firewallrules
from cgtsclient.v1 import partition
from cgtsclient.v1 import certificate
from cgtsclient.v1 import storage_tier


class Client(http.HTTPClient):
    """Client for the Cgts v1 API.

    :param string endpoint: A user-supplied endpoint URL for the cgts
                            service.
    :param function token: Provides token for authentication.
    :param integer timeout: Allows customization of the timeout for client
                            http requests. (optional)
    """

    def __init__(self, *args, **kwargs):
        """Initialize a new client for the Cgts v1 API."""
        super(Client, self).__init__(*args, **kwargs)
        self.smapi_endpoint = kwargs.get('smapi_endpoint')

        self.isystem = isystem.isystemManager(self)
        self.ihost = ihost.ihostManager(self)
        self.inode = inode.inodeManager(self)
        self.icpu = icpu.icpuManager(self)
        self.imemory = imemory.imemoryManager(self)
        self.iinterface = iinterface.iinterfaceManager(self)
        self.idisk = idisk.idiskManager(self)
        self.istor = istor.istorManager(self)
        self.ipv = ipv.ipvManager(self)
        self.ilvg = ilvg.ilvgManager(self)
        self.iuser = iuser.iuserManager(self)
        self.idns = idns.idnsManager(self)
        self.intp = intp.intpManager(self)
        self.iextoam = iextoam.iextoamManager(self)
        self.controller_fs = controller_fs.ControllerFsManager(self)
        self.storage_backend = storage_backend.StorageBackendManager(self)
        self.storage_lvm  = storage_lvm.StorageLvmManager(self)
        self.storage_file  = storage_file.StorageFileManager(self)
        self.storage_external = storage_external.StorageExternalManager(self)
        self.storage_ceph = storage_ceph.StorageCephManager(self)
        self.ceph_mon = ceph_mon.CephMonManager(self)
        self.drbdconfig = drbdconfig.drbdconfigManager(self)
        self.iprofile = iprofile.iprofileManager(self)
        self.icommunity = icommunity.iCommunityManager(self)
        self.itrapdest = itrapdest.iTrapdestManager(self)
        self.ialarm = ialarm.ialarmManager(self)
        self.event_log = event_log.EventLogManager(self)
        self.event_suppression = event_suppression.EventSuppressionManager(self)
        self.iinfra = iinfra.iinfraManager(self)
        self.port = port.PortManager(self)
        self.ethernet_port = ethernetport.EthernetPortManager(self)
        self.address = address.AddressManager(self)
        self.address_pool = address_pool.AddressPoolManager(self)
        self.route = route.RouteManager(self)
        self.isensor = isensor.isensorManager(self)
        self.isensorgroup = isensorgroup.isensorgroupManager(self)
        self.pci_device = pci_device.PciDeviceManager(self)
        self.load = load.LoadManager(self)
        self.upgrade = upgrade.UpgradeManager(self)
        self.network = network.NetworkManager(self)
        self.service_parameter = service_parameter.ServiceParameterManager(self)
        self.cluster = cluster.ClusterManager(self)
        self.lldp_agent = lldp_agent.LldpAgentManager(self)
        self.lldp_neighbour = lldp_neighbour.LldpNeighbourManager(self)
        self.sm_service_nodes = sm_service_nodes.SmNodesManager(self)
        self.sm_service = sm_service.SmServiceManager(self)
        self.sm_servicegroup = sm_servicegroup.SmServiceGroupManager(self)
        self.health = health.HealthManager(self)
        self.remotelogging = remotelogging.RemoteLoggingManager(self)
        self.sdn_controller = sdn_controller.SDNControllerManager(self)
        self.tpmconfig = tpmconfig.TpmConfigManager(self)
        self.firewallrules = firewallrules.FirewallRulesManager(self)
        self.partition = partition.partitionManager(self)
        self.license = license.LicenseManager(self)
        self.certificate = certificate.CertificateManager(self)
        self.storage_tier = storage_tier.StorageTierManager(self)
