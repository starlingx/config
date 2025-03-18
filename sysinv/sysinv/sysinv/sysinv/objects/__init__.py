#    Copyright 2013 IBM Corp.
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
# Copyright (c) 2013-2024 Wind River Systems, Inc.
#

from sysinv.objects import address
from sysinv.objects import address_mode
from sysinv.objects import address_pool
from sysinv.objects import ceph_mon
from sysinv.objects import certificate
from sysinv.objects import cluster
from sysinv.objects import controller_fs
from sysinv.objects import cpu
from sysinv.objects import datanetwork
from sysinv.objects import device_image
from sysinv.objects import device_image_label
from sysinv.objects import device_image_state
from sysinv.objects import device_label
from sysinv.objects import disk
from sysinv.objects import fpga_device
from sysinv.objects import partition
from sysinv.objects import dns
from sysinv.objects import drbdconfig
from sysinv.objects import port_ethernet
from sysinv.objects import helm_overrides
from sysinv.objects import host
from sysinv.objects import kube_app
from sysinv.objects import kube_app_bundle
from sysinv.objects import kube_app_releases
from sysinv.objects import kube_host_upgrade
from sysinv.objects import kube_upgrade
from sysinv.objects import kube_version
from sysinv.objects import kube_cmd_version
from sysinv.objects import interface
from sysinv.objects import interface_ae
from sysinv.objects import interface_ethernet
from sysinv.objects import interface_datanetwork
from sysinv.objects import interface_network
from sysinv.objects import interface_vf
from sysinv.objects import interface_virtual
from sysinv.objects import interface_vlan
from sysinv.objects import journal
from sysinv.objects import label
from sysinv.objects import lldp_agent
from sysinv.objects import lldp_neighbour
from sysinv.objects import lldp_tlv
from sysinv.objects import lvg
from sysinv.objects import memory
from sysinv.objects import network
from sysinv.objects import network_oam
from sysinv.objects import network_addrpool
from sysinv.objects import node
from sysinv.objects import ntp
from sysinv.objects import pci_device
from sysinv.objects import peer
from sysinv.objects import port
from sysinv.objects import ptp
from sysinv.objects import ptp_instance
from sysinv.objects import ptp_instance_map
from sysinv.objects import ptp_interface
from sysinv.objects import ptp_interface_map
from sysinv.objects import ptp_parameter
from sysinv.objects import ptp_paramowner
from sysinv.objects import ptp_paramownership
from sysinv.objects import pv
from sysinv.objects import remote_logging
from sysinv.objects import route
from sysinv.objects import sdn_controller
from sysinv.objects import sensor
from sysinv.objects import sensor_analog
from sysinv.objects import sensor_discrete
from sysinv.objects import sensorgroup
from sysinv.objects import sensorgroup_analog
from sysinv.objects import sensorgroup_discrete
from sysinv.objects import service_parameter
from sysinv.objects import storage
from sysinv.objects import storage_backend
from sysinv.objects import storage_ceph
from sysinv.objects import storage_lvm
from sysinv.objects import system
from sysinv.objects import user
from sysinv.objects import service
from sysinv.objects import tpmconfig
from sysinv.objects import tpmdevice
from sysinv.objects import storage_file
from sysinv.objects import storage_external
from sysinv.objects import storage_tier
from sysinv.objects import storage_ceph_external
from sysinv.objects import storage_ceph_rook
from sysinv.objects import host_fs
from sysinv.objects import restore
from sysinv.objects import kube_rootca_update
from sysinv.objects import kube_rootca_host_update
from sysinv.objects import runtime_config


# alias objects for RPC compatibility
ihost = host.ihost
ilvg = lvg.LVG

system = system.System
cluster = cluster.Cluster
peer = peer.Peer
host = host.Host
node = node.Node
cpu = cpu.CPU
memory = memory.Memory
interface = interface.Interface
ethernet_interface = interface_ethernet.EthernetInterface
ae_interface = interface_ae.AEInterface
virtual_interface = interface_virtual.VirtualInterface
vlan_interface = interface_vlan.VLANInterface
sriov_vf_interface = interface_vf.SriovVFInterface
interface_network = interface_network.InterfaceNetwork
interface_datanetwork = interface_datanetwork.InterfaceDataNetwork
port = port.Port
ethernet_port = port_ethernet.EthernetPort
disk = disk.Disk
partition = partition.Partition
storage = storage.Storage
journal = journal.Journal
lvg = lvg.LVG
pv = pv.PV
user = user.User
dns = dns.DNS
ntp = ntp.NTP
ptp = ptp.PTP
ptp_instance = ptp_instance.PtpInstance
ptp_instance_map = ptp_instance_map.PtpInstanceMap
ptp_interface = ptp_interface.PtpInterface
ptp_interface_map = ptp_interface_map.PtpInterfaceMap
ptp_parameter = ptp_parameter.PtpParameter
ptp_paramowner = ptp_paramowner.PtpParameterOwner
ptp_paramownership = ptp_paramownership.PtpParameterOwnership
oam_network = network_oam.OAMNetwork
storage_backend = storage_backend.StorageBackend
storage_ceph = storage_ceph.StorageCeph
storage_lvm = storage_lvm.StorageLVM
ceph_mon = ceph_mon.CephMon
controller_fs = controller_fs.ControllerFS
drbdconfig = drbdconfig.DRBDConfig
address = address.Address
address_pool = address_pool.AddressPool
route = route.Route
address_mode = address_mode.AddressMode
network = network.Network
sensor = sensor.Sensor
sensor_analog = sensor_analog.SensorAnalog
sensor_discrete = sensor_discrete.SensorDiscrete
sensorgroup = sensorgroup.SensorGroup
sensorgroup_analog = sensorgroup_analog.SensorGroupAnalog
sensorgroup_discrete = sensorgroup_discrete.SensorGroupDiscrete
pci_device = pci_device.PCIDevice
service_parameter = service_parameter.ServiceParameter
lldp_agent = lldp_agent.LLDPAgent
lldp_neighbour = lldp_neighbour.LLDPNeighbour
lldp_tlv = lldp_tlv.LLDPTLV
remotelogging = remote_logging.RemoteLogging
sdn_controller = sdn_controller.SDNController
service = service.Service
tpmconfig = tpmconfig.TPMConfig
tpmdevice = tpmdevice.TPMDevice
certificate = certificate.Certificate
storage_file = storage_file.StorageFile
storage_external = storage_external.StorageExternal
storage_tier = storage_tier.StorageTier
storage_ceph_external = storage_ceph_external.StorageCephExternal
storage_ceph_rook = storage_ceph_rook.StorageCephRook
helm_overrides = helm_overrides.HelmOverrides
label = label.Label
kube_app = kube_app.KubeApp
kube_app_bundle = kube_app_bundle.KubeAppBundle
kube_app_releases = kube_app_releases.KubeAppReleases
kube_host_upgrade = kube_host_upgrade.KubeHostUpgrade
kube_upgrade = kube_upgrade.KubeUpgrade
kube_version = kube_version.KubeVersion
kube_cmd_version = kube_cmd_version.KubeCmdVersion
datanetwork = datanetwork.DataNetwork
host_fs = host_fs.HostFS
device_image = device_image.DeviceImage
device_image_label = device_image_label.DeviceImageLabel
device_image_state = device_image_state.DeviceImageState
device_label = device_label.DeviceLabel
fpga_device = fpga_device.FPGADevice
restore = restore.Restore
kube_rootca_host_update = kube_rootca_host_update.KubeRootCAHostUpdate
kube_rootca_update = kube_rootca_update.KubeRootCAUpdate
runtime_config = runtime_config.RuntimeConfig
network_addrpool = network_addrpool.NetworkAddrpool

__all__ = ("system",
           "cluster",
           "peer",
           "host",
           "node",
           "cpu",
           "memory",
           "interface",
           "ethernet_interface",
           "ae_interface",
           "vlan_interface",
           "port",
           "ethernet_port",
           "virtual_interface",
           "disk",
           "storage",
           "journal",
           "lvg",
           "pv",
           "user",
           "dns",
           "ntp",
           "ptp",
           "ptp_instance",
           "ptp_instance_map",
           "ptp_interface",
           "ptp_interface_map",
           "ptp_parameter",
           "ptp_paramowner",
           "ptp_paramownership",
           "oam_network",
           "storage_backend",
           "storage_ceph",
           "storage_lvm",
           "ceph_mon",
           "drbdconfig",
           "address",
           "address_mode",
           "route",
           "sensor",
           "sensor_analog",
           "sensor_discrete",
           "sensorgroup",
           "sensorgroup_analog",
           "sensorgroup_discrete",
           "pci_device",
           "network",
           "interface_network",
           "service_parameter",
           "label",
           "lldp_agent",
           "lldp_neighbour",
           "lldp_tlv",
           "remotelogging",
           "sdn_controller",
           "service",
           "tpmconfig",
           "tpmdevice",
           "certificate",
           "storage_file",
           "storage_external",
           "storage_ceph_rook",
           "storage_tier",
           "storage_ceph_external",
           "helm_overrides",
           "kube_app",
           "kube_app_bundle",
           "kube_app_releases",
           "kube_host_upgrade",
           "kube_upgrade",
           "kube_version",
           "kube_cmd_version",
           "datanetwork",
           "interface_network",
           "host_fs",
           "device_image",
           "device_image_label",
           "device_label",
           "fpga_device",
           "restore",
           "kube_rootca_host_update",
           "kube_rootca_update",
           "runtime_config",
           "network_addrpool",
           # alias objects for RPC compatibility
           "ihost",
           "ilvg")
