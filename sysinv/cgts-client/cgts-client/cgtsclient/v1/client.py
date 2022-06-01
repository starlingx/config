# Copyright 2012-2021 OpenStack LLC.
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
# Copyright (c) 2013-2021 Wind River Systems, Inc.
#


from cgtsclient.common import http
from cgtsclient.v1 import address
from cgtsclient.v1 import address_pool
from cgtsclient.v1 import app
from cgtsclient.v1 import ceph_mon
from cgtsclient.v1 import certificate
from cgtsclient.v1 import cluster
from cgtsclient.v1 import controller_fs
from cgtsclient.v1 import datanetwork
from cgtsclient.v1 import device_image
from cgtsclient.v1 import device_image_state
from cgtsclient.v1 import device_label
from cgtsclient.v1 import drbdconfig
from cgtsclient.v1 import ethernetport
from cgtsclient.v1 import fernet
from cgtsclient.v1 import health
from cgtsclient.v1 import helm
from cgtsclient.v1 import host_fs
from cgtsclient.v1 import icpu
from cgtsclient.v1 import idisk
from cgtsclient.v1 import idns
from cgtsclient.v1 import iextoam
from cgtsclient.v1 import ihost
from cgtsclient.v1 import iinterface
from cgtsclient.v1 import ilvg
from cgtsclient.v1 import imemory
from cgtsclient.v1 import inode
from cgtsclient.v1 import interface_datanetwork
from cgtsclient.v1 import interface_network
from cgtsclient.v1 import intp
from cgtsclient.v1 import ipv
from cgtsclient.v1 import isensor
from cgtsclient.v1 import isensorgroup
from cgtsclient.v1 import istor
from cgtsclient.v1 import isystem
from cgtsclient.v1 import iuser
from cgtsclient.v1 import kube_cluster
from cgtsclient.v1 import kube_cmd_version
from cgtsclient.v1 import kube_config_kubelet
from cgtsclient.v1 import kube_host_upgrade
from cgtsclient.v1 import kube_rootca_update
from cgtsclient.v1 import kube_upgrade
from cgtsclient.v1 import kube_version
from cgtsclient.v1 import label
from cgtsclient.v1 import license
from cgtsclient.v1 import lldp_agent
from cgtsclient.v1 import lldp_neighbour
from cgtsclient.v1 import load
from cgtsclient.v1 import network
from cgtsclient.v1 import partition
from cgtsclient.v1 import pci_device
from cgtsclient.v1 import port
from cgtsclient.v1 import ptp
from cgtsclient.v1 import ptp_instance
from cgtsclient.v1 import ptp_interface
from cgtsclient.v1 import ptp_parameter
from cgtsclient.v1 import registry_image
from cgtsclient.v1 import remotelogging
from cgtsclient.v1 import restore
from cgtsclient.v1 import route
from cgtsclient.v1 import sdn_controller
from cgtsclient.v1 import service_parameter
from cgtsclient.v1 import sm_service
from cgtsclient.v1 import sm_service_nodes
from cgtsclient.v1 import sm_servicegroup
from cgtsclient.v1 import storage_backend
from cgtsclient.v1 import storage_ceph
from cgtsclient.v1 import storage_ceph_external
from cgtsclient.v1 import storage_ceph_rook
from cgtsclient.v1 import storage_external
from cgtsclient.v1 import storage_file
from cgtsclient.v1 import storage_lvm
from cgtsclient.v1 import storage_tier
from cgtsclient.v1 import upgrade


class Client(object):
    """Client for the Cgts v1 API.

    :param string endpoint: A user-supplied endpoint URL for the cgts
                            service.
    :param function token: Provides token for authentication.
    :param integer timeout: Allows customization of the timeout for client
                            http requests. (optional)
    """

    def __init__(self, *args, **kwargs):
        """Initialize a new client for the Cgts v1 API."""
        super(Client, self).__init__()
        self.http_client = http.construct_http_client(*args, **kwargs)

        self.isystem = isystem.isystemManager(self.http_client)
        self.ihost = ihost.ihostManager(self.http_client)
        self.inode = inode.inodeManager(self.http_client)
        self.icpu = icpu.icpuManager(self.http_client)
        self.imemory = imemory.imemoryManager(self.http_client)
        self.iinterface = iinterface.iinterfaceManager(self.http_client)
        self.idisk = idisk.idiskManager(self.http_client)
        self.istor = istor.istorManager(self.http_client)
        self.ipv = ipv.ipvManager(self.http_client)
        self.ilvg = ilvg.ilvgManager(self.http_client)
        self.iuser = iuser.iuserManager(self.http_client)
        self.idns = idns.idnsManager(self.http_client)
        self.intp = intp.intpManager(self.http_client)
        self.ptp = ptp.ptpManager(self.http_client)
        self.ptp_instance = ptp_instance.PtpInstanceManager(self.http_client)
        self.ptp_interface = ptp_interface.PtpInterfaceManager(self.http_client)
        self.ptp_parameter = ptp_parameter.PtpParameterManager(self.http_client)
        self.iextoam = iextoam.iextoamManager(self.http_client)
        self.controller_fs = controller_fs.ControllerFsManager(self.http_client)
        self.storage_backend = storage_backend.StorageBackendManager(self.http_client)
        self.storage_lvm = storage_lvm.StorageLvmManager(self.http_client)
        self.storage_file = storage_file.StorageFileManager(self.http_client)
        self.storage_external = storage_external.StorageExternalManager(self.http_client)
        self.storage_ceph = storage_ceph.StorageCephManager(self.http_client)
        self.storage_ceph_rook = storage_ceph_rook.StorageCephRookManager(self.http_client)
        self.ceph_mon = ceph_mon.CephMonManager(self.http_client)
        self.drbdconfig = drbdconfig.drbdconfigManager(self.http_client)
        self.port = port.PortManager(self.http_client)
        self.ethernet_port = ethernetport.EthernetPortManager(self.http_client)
        self.address = address.AddressManager(self.http_client)
        self.address_pool = address_pool.AddressPoolManager(self.http_client)
        self.route = route.RouteManager(self.http_client)
        self.isensor = isensor.isensorManager(self.http_client)
        self.isensorgroup = isensorgroup.isensorgroupManager(self.http_client)
        self.pci_device = pci_device.PciDeviceManager(self.http_client)
        self.load = load.LoadManager(self.http_client)
        self.upgrade = upgrade.UpgradeManager(self.http_client)
        self.network = network.NetworkManager(self.http_client)
        self.datanetwork = datanetwork.DataNetworkManager(self.http_client)
        self.interface_datanetwork = \
            interface_datanetwork.InterfaceDataNetworkManager(self.http_client)
        self.interface_network = interface_network.InterfaceNetworkManager(self.http_client)
        self.service_parameter = service_parameter.ServiceParameterManager(self.http_client)
        self.cluster = cluster.ClusterManager(self.http_client)
        self.lldp_agent = lldp_agent.LldpAgentManager(self.http_client)
        self.lldp_neighbour = lldp_neighbour.LldpNeighbourManager(self.http_client)
        self.sm_service_nodes = sm_service_nodes.SmNodesManager(self.http_client)
        self.sm_service = sm_service.SmServiceManager(self.http_client)
        self.sm_servicegroup = sm_servicegroup.SmServiceGroupManager(self.http_client)
        self.health = health.HealthManager(self.http_client)
        self.registry_image = registry_image.RegistryImageManager(self.http_client)
        self.remotelogging = remotelogging.RemoteLoggingManager(self.http_client)
        self.sdn_controller = sdn_controller.SDNControllerManager(self.http_client)
        self.partition = partition.partitionManager(self.http_client)
        self.license = license.LicenseManager(self.http_client)
        self.certificate = certificate.CertificateManager(self.http_client)
        self.storage_tier = storage_tier.StorageTierManager(self.http_client)
        self.storage_ceph_external = \
            storage_ceph_external.StorageCephExternalManager(self.http_client)
        self.helm = helm.HelmManager(self.http_client)
        self.label = label.KubernetesLabelManager(self.http_client)
        self.fernet = fernet.FernetManager(self.http_client)
        self.app = app.AppManager(self.http_client)
        self.host_fs = host_fs.HostFsManager(self.http_client)
        self.kube_cluster = kube_cluster.KubeClusterManager(self.http_client)
        self.kube_version = kube_version.KubeVersionManager(self.http_client)
        self.kube_cmd_version = kube_cmd_version.KubeCmdVersionManager(self.http_client)
        self.kube_upgrade = kube_upgrade.KubeUpgradeManager(self.http_client)
        self.kube_host_upgrade = kube_host_upgrade.KubeHostUpgradeManager(self.http_client)
        self.device_image = device_image.DeviceImageManager(self.http_client)
        self.device_image_state = device_image_state.DeviceImageStateManager(self.http_client)
        self.device_label = device_label.DeviceLabelManager(self.http_client)
        self.restore = restore.RestoreManager(self.http_client)
        self.kube_rootca_update = kube_rootca_update.KubeRootCAUpdateManager(self.http_client)
        self.kube_config_kubelet = \
            kube_config_kubelet.KubeConfigKubeletManager(self.http_client)
