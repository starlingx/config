#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

"""
Version 1 of the Sysinv API

Specification can be found in WADL.
"""

import pecan
import wsmeext.pecan as wsme_pecan
from pecan import rest
from wsme import types as wtypes

from sysinv.api.controllers.v1 import address
from sysinv.api.controllers.v1 import address_pool
from sysinv.api.controllers.v1 import alarm
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import ceph_mon
from sysinv.api.controllers.v1 import cluster
from sysinv.api.controllers.v1 import community
from sysinv.api.controllers.v1 import controller_fs
from sysinv.api.controllers.v1 import cpu
from sysinv.api.controllers.v1 import disk
from sysinv.api.controllers.v1 import dns
from sysinv.api.controllers.v1 import drbdconfig
from sysinv.api.controllers.v1 import ethernet_port
from sysinv.api.controllers.v1 import event_log
from sysinv.api.controllers.v1 import event_suppression
from sysinv.api.controllers.v1 import firewallrules
from sysinv.api.controllers.v1 import health
from sysinv.api.controllers.v1 import host
from sysinv.api.controllers.v1 import interface
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import lldp_agent
from sysinv.api.controllers.v1 import lldp_neighbour
from sysinv.api.controllers.v1 import load
from sysinv.api.controllers.v1 import lvg
from sysinv.api.controllers.v1 import license
from sysinv.api.controllers.v1 import memory
from sysinv.api.controllers.v1 import network
from sysinv.api.controllers.v1 import network_infra
from sysinv.api.controllers.v1 import network_oam
from sysinv.api.controllers.v1 import node
from sysinv.api.controllers.v1 import ntp
from sysinv.api.controllers.v1 import partition
from sysinv.api.controllers.v1 import pci_device
from sysinv.api.controllers.v1 import port
from sysinv.api.controllers.v1 import profile
from sysinv.api.controllers.v1 import pv
from sysinv.api.controllers.v1 import remotelogging
from sysinv.api.controllers.v1 import route
from sysinv.api.controllers.v1 import sdn_controller
from sysinv.api.controllers.v1 import certificate
from sysinv.api.controllers.v1 import sensor
from sysinv.api.controllers.v1 import sensorgroup
from sysinv.api.controllers.v1 import service
from sysinv.api.controllers.v1 import service_parameter
from sysinv.api.controllers.v1 import servicegroup
from sysinv.api.controllers.v1 import servicenode
from sysinv.api.controllers.v1 import storage
from sysinv.api.controllers.v1 import storage_backend
from sysinv.api.controllers.v1 import storage_ceph
from sysinv.api.controllers.v1 import storage_lvm
from sysinv.api.controllers.v1 import storage_file
from sysinv.api.controllers.v1 import storage_external
from sysinv.api.controllers.v1 import storage_tier
from sysinv.api.controllers.v1 import system
from sysinv.api.controllers.v1 import trapdest
from sysinv.api.controllers.v1 import tpmconfig
from sysinv.api.controllers.v1 import upgrade
from sysinv.api.controllers.v1 import user


class MediaType(base.APIBase):
    """A media type representation."""

    base = wtypes.text
    type = wtypes.text

    def __init__(self, base, type):
        self.base = base
        self.type = type


class V1(base.APIBase):
    """The representation of the version 1 of the API."""

    id = wtypes.text
    "The ID of the version, also acts as the release number"

    media_types = [MediaType]
    "An array of supported media types for this version"

    links = [link.Link]
    "Links that point to a specific URL for this version and documentation"

    isystems = [link.Link]
    "Links to the isystems resource"

    ihosts = [link.Link]
    "Links to the ihosts resource"

    inode = [link.Link]
    "Links to the inode resource"

    icpu = [link.Link]
    "Links to the icpu resource"

    imemory = [link.Link]
    "Links to the imemory resource"

    iprofile = [link.Link]
    "Links to the iprofile resource"

    itrapdest = [link.Link]
    "Links to the itrapdest node cluster resource"

    icommunity = [link.Link]
    "Links to the icommunity node cluster resource"

    ialarms = [link.Link]
    "Links to the ialarm resource"

    event_log = [link.Link]
    "Links to the event_log resource"

    event_suppression = [link.Link]
    "Links to the event_suppression resource"

    iuser = [link.Link]
    "Links to the iuser resource"

    idns = [link.Link]
    "Links to the idns resource"

    intp = [link.Link]
    "Links to the intp resource"

    iextoam = [link.Link]
    "Links to the iextoam resource"

    controller_fs = [link.Link]
    "Links to the controller_fs resource"

    storage_backend = [link.Link]
    "Links to the storage backend resource"

    storage_lvm = [link.Link]
    "Links to the storage lvm resource"

    storage_file = [link.Link]
    "Links to the storage file resource"

    storage_external = [link.Link]
    "Links to the storage external resource"

    storage_ceph = [link.Link]
    "Links to the storage ceph resource"

    storage_tier = [link.Link]
    "Links to the storage tier resource"

    ceph_mon = [link.Link]
    "Links to the ceph mon resource"

    drbdconfig = [link.Link]
    "Links to the drbdconfig resource"

    iinfra = [link.Link]
    "Links to the iinfra resource"

    addresses = [link.Link]
    "Links to the addresses resource"

    addrpools = [link.Link]
    "Links to the address pool resource"

    upgrade = [link.Link]
    "Links to the software upgrade resource"

    networks = [link.Link]
    "Links to the network resource"

    service_parameter = [link.Link]
    "Links to the service parameter resource"

    clusters = [link.Link]
    "Links to the cluster resource"

    lldp_agents = [link.Link]
    "Links to the lldp agents resource"

    lldp_neighbours = [link.Link]
    "Links to the lldp neighbours resource"

    services = [link.Link]
    "Links to the sm_service resource"

    servicenodes = [link.Link]
    "Links to the sm_nodes resource"

    servicegroup = [link.Link]
    "Links to the servicegroup resource"

    health = [link.Link]
    "Links to the system health resource"

    remotelogging = [link.Link]
    "Links to the remotelogging resource"

    sdn_controller = [link.Link]
    "Links to the SDN controller resource"

    tpmconfig = [link.Link]
    "Links to the TPM configuration resource"

    firewallrules = [link.Link]
    "Links to customer firewall rules"

    license = [link.Link]
    "Links to the license resource "

    @classmethod
    def convert(self):
        v1 = V1()
        v1.id = "v1"
        v1.links = [link.Link.make_link('self', pecan.request.host_url,
                                        'v1', '', bookmark=True),
                    link.Link.make_link('describedby',
                                        'http://www.windriver.com',
                                        'developer/sysinv/dev',
                                        'api-spec-v1.html',
                                        bookmark=True, type='text/html')
                    ]
        v1.media_types = [MediaType('application/json',
                          'application/vnd.openstack.sysinv.v1+json')]

        v1.isystems = [link.Link.make_link('self', pecan.request.host_url,
                                           'isystems', ''),
                       link.Link.make_link('bookmark',
                                           pecan.request.host_url,
                                           'isystems', '',
                                           bookmark=True)
                       ]

        v1.ihosts = [link.Link.make_link('self', pecan.request.host_url,
                                        'ihosts', ''),
                    link.Link.make_link('bookmark',
                                        pecan.request.host_url,
                                        'ihosts', '',
                                        bookmark=True)
                     ]

        v1.inode = [link.Link.make_link('self', pecan.request.host_url,
                                        'inode', ''),
                    link.Link.make_link('bookmark',
                                        pecan.request.host_url,
                                        'inode', '',
                                        bookmark=True)
                    ]

        v1.icpu = [link.Link.make_link('self', pecan.request.host_url,
                                        'icpu', ''),
                    link.Link.make_link('bookmark',
                                        pecan.request.host_url,
                                        'icpu', '',
                                        bookmark=True)
                   ]

        v1.imemory = [link.Link.make_link('self', pecan.request.host_url,
                                          'imemory', ''),
                      link.Link.make_link('bookmark',
                                          pecan.request.host_url,
                                          'imemory', '',
                                          bookmark=True)
                      ]

        v1.iprofile = [link.Link.make_link('self', pecan.request.host_url,
                                        'iprofile', ''),
                       link.Link.make_link('bookmark',
                                        pecan.request.host_url,
                                        'iprofile', '',
                                        bookmark=True)
                       ]

        v1.iinterfaces = [link.Link.make_link('self',
                                        pecan.request.host_url,
                                        'iinterfaces', ''),
                    link.Link.make_link('bookmark',
                                        pecan.request.host_url,
                                        'iinterfaces', '',
                                        bookmark=True)
                          ]

        v1.ports = [link.Link.make_link('self',
                                        pecan.request.host_url,
                                        'ports', ''),
                    link.Link.make_link('bookmark',
                                        pecan.request.host_url,
                                        'ports', '',
                                        bookmark=True)
                    ]
        v1.ethernet_ports = [link.Link.make_link('self',
                                        pecan.request.host_url,
                                        'ethernet_ports', ''),
                    link.Link.make_link('bookmark',
                                        pecan.request.host_url,
                                        'ethernet_ports', '',
                                        bookmark=True)
                             ]
        v1.istors = [link.Link.make_link('self',
                                        pecan.request.host_url,
                                        'istors', ''),
                    link.Link.make_link('bookmark',
                                        pecan.request.host_url,
                                        'istors', '',
                                        bookmark=True)
                     ]

        v1.idisks = [link.Link.make_link('self',
                                        pecan.request.host_url,
                                        'idisks', ''),
                    link.Link.make_link('bookmark',
                                        pecan.request.host_url,
                                        'idisks', '',
                                        bookmark=True)
                     ]

        v1.partitions = [link.Link.make_link('self',
                                         pecan.request.host_url,
                                         'partitions', ''),
                     link.Link.make_link('bookmark',
                                         pecan.request.host_url,
                                         'partitions', '',
                                         bookmark=True)
                         ]

        v1.ilvgs = [link.Link.make_link('self',
                                        pecan.request.host_url,
                                        'ilvgs', ''),
                    link.Link.make_link('bookmark',
                                        pecan.request.host_url,
                                        'ilvgs', '',
                                        bookmark=True)
                    ]

        v1.ipvs = [link.Link.make_link('self',
                                       pecan.request.host_url,
                                       'ipvs', ''),
                   link.Link.make_link('bookmark',
                                       pecan.request.host_url,
                                       'ipvs', '',
                                       bookmark=True)
                   ]

        v1.itrapdest = [link.Link.make_link('self', pecan.request.host_url,
                                            'itrapdest', ''),
                       link.Link.make_link('bookmark',
                                           pecan.request.host_url,
                                           'itrapdest', '',
                                           bookmark=True)
                        ]

        v1.icommunity = [link.Link.make_link('self', pecan.request.host_url,
                                             'icommunity', ''),
                       link.Link.make_link('bookmark',
                                           pecan.request.host_url,
                                           'icommunity', '',
                                           bookmark=True)
                         ]

        v1.iuser = [link.Link.make_link('self', pecan.request.host_url,
                                        'iuser', ''),
                      link.Link.make_link('bookmark',
                                          pecan.request.host_url,
                                          'iuser', '',
                                          bookmark=True)
                    ]

        v1.idns = [link.Link.make_link('self', pecan.request.host_url,
                                          'idns', ''),
                      link.Link.make_link('bookmark',
                                           pecan.request.host_url,
                                           'idns', '',
                                           bookmark=True)
                   ]

        v1.intp = [link.Link.make_link('self', pecan.request.host_url,
                                          'intp', ''),
                      link.Link.make_link('bookmark',
                                           pecan.request.host_url,
                                           'intp', '',
                                           bookmark=True)
                   ]

        v1.iextoam = [link.Link.make_link('self', pecan.request.host_url,
                                          'iextoam', ''),
                      link.Link.make_link('bookmark',
                                           pecan.request.host_url,
                                           'iextoam', '',
                                           bookmark=True)
                      ]

        v1.controller_fs = [link.Link.make_link('self', pecan.request.host_url,
                                                'controller_fs', ''),
                            link.Link.make_link('bookmark',
                                                 pecan.request.host_url,
                                                 'controller_fs', '',
                                                 bookmark=True)
                            ]

        v1.storage_backend = [link.Link.make_link('self',
                                                   pecan.request.host_url,
                                                  'storage_backend', ''),
                              link.Link.make_link('bookmark',
                                                  pecan.request.host_url,
                                                  'storage_backend', '',
                                                  bookmark=True)
                              ]

        v1.storage_lvm = [link.Link.make_link('self',
                                              pecan.request.host_url,
                                              'storage_lvm', ''),
                          link.Link.make_link('bookmark',
                                              pecan.request.host_url,
                                              'storage_lvm', '',
                                              bookmark=True)
                          ]

        v1.storage_file = [link.Link.make_link('self',
                                               pecan.request.host_url,
                                               'storage_file', ''),
                           link.Link.make_link('bookmark',
                                               pecan.request.host_url,
                                               'storage_file', '',
                                               bookmark=True)
                           ]

        v1.storage_external = [link.Link.make_link('self',
                                                   pecan.request.host_url,
                                                   'storage_external', ''),
                               link.Link.make_link('bookmark',
                                                   pecan.request.host_url,
                                                   'storage_external', '',
                                                   bookmark=True)
                               ]

        v1.storage_ceph = [link.Link.make_link('self',
                                               pecan.request.host_url,
                                               'storage_ceph', ''),
                           link.Link.make_link('bookmark',
                                               pecan.request.host_url,
                                               'storage_ceph', '',
                                               bookmark=True)
                           ]

        v1.ceph_mon = [link.Link.make_link('self',
                                           pecan.request.host_url,
                                           'ceph_mon', ''),
                       link.Link.make_link('bookmark',
                                           pecan.request.host_url,
                                           'ceph_mon', '',
                                           bookmark=True)
                       ]

        v1.storage_tiers = [link.Link.make_link('self',
                                                pecan.request.host_url,
                                                'storage_tiers', ''),
                            link.Link.make_link('bookmark',
                                                pecan.request.host_url,
                                                'storage_tiers', '',
                                                bookmark=True)
                            ]

        v1.drbdconfig = [link.Link.make_link('self', pecan.request.host_url,
                                             'drbdconfig', ''),
                      link.Link.make_link('bookmark',
                                           pecan.request.host_url,
                                           'drbdconfig', '',
                                           bookmark=True)
                         ]

        v1.ialarms = [link.Link.make_link('self', pecan.request.host_url,
                                         'ialarms', ''),
                     link.Link.make_link('bookmark',
                                         pecan.request.host_url,
                                         'ialarms', '',
                                         bookmark=True)
                      ]

        v1.event_log = [link.Link.make_link('self', pecan.request.host_url,
                                                 'event_log', ''),
                            link.Link.make_link('bookmark',
                                                 pecan.request.host_url,
                                                 'event_log', '',
                                                 bookmark=True)
                        ]

        v1.event_suppression = [link.Link.make_link('self', pecan.request.host_url,
                                                 'event_suppression', ''),
                                link.Link.make_link('bookmark',
                                                 pecan.request.host_url,
                                                 'event_suppression', '',
                                                 bookmark=True)
                                ]

        v1.iinfra = [link.Link.make_link('self', pecan.request.host_url,
                                          'iinfra', ''),
                      link.Link.make_link('bookmark',
                                           pecan.request.host_url,
                                           'iinfra', '',
                                           bookmark=True)
                     ]
        v1.addresses = [link.Link.make_link('self', pecan.request.host_url,
                                            'addresses', ''),
                        link.Link.make_link('bookmark',
                                            pecan.request.host_url,
                                            'addresses', '',
                                            bookmark=True)
                        ]
        v1.addrpools = [link.Link.make_link('self', pecan.request.host_url,
                                            'addrpools', ''),
                        link.Link.make_link('bookmark',
                                            pecan.request.host_url,
                                            'addrpools', '',
                                            bookmark=True)
                        ]
        v1.routes = [link.Link.make_link('self', pecan.request.host_url,
                                         'routes', ''),
                     link.Link.make_link('bookmark',
                                         pecan.request.host_url,
                                         'routes', '',
                                         bookmark=True)
                     ]

        v1.certificate = [link.Link.make_link('self',
                                         pecan.request.host_url,
                                         'certificate', ''),
                          link.Link.make_link('bookmark',
                                         pecan.request.host_url,
                                         'certificate', '',
                                         bookmark=True)
                          ]

        v1.isensors = [link.Link.make_link('self',
                                           pecan.request.host_url,
                                           'isensors', ''),
                       link.Link.make_link('bookmark',
                                           pecan.request.host_url,
                                           'isensors', '',
                                           bookmark=True)
                       ]

        v1.isensorgroups = [link.Link.make_link('self',
                                                pecan.request.host_url,
                                                'isensorgroups', ''),
                            link.Link.make_link('bookmark',
                                                pecan.request.host_url,
                                                'isensorgroups', '',
                                                bookmark=True)
                            ]

        v1.loads = [link.Link.make_link('self', pecan.request.host_url,
                                        'loads', ''),
                    link.Link.make_link('bookmark', pecan.request.host_url,
                                        'loads', '', bookmark=True)
                    ]

        v1.pci_devices = [link.Link.make_link('self',
                                              pecan.request.host_url,
                                              'pci_devices', ''),
                          link.Link.make_link('bookmark',
                                              pecan.request.host_url,
                                              'pci_devices', '',
                                              bookmark=True)
                          ]

        v1.upgrade = [link.Link.make_link('self', pecan.request.host_url,
                                          'upgrade', ''),
                      link.Link.make_link('bookmark',
                                          pecan.request.host_url,
                                          'upgrade', '',
                                          bookmark=True)
                      ]

        v1.networks = [link.Link.make_link('self', pecan.request.host_url,
                                           'networks', ''),
                       link.Link.make_link('bookmark',
                                           pecan.request.host_url,
                                           'networks', '',
                                           bookmark=True)
                       ]
        v1.service_parameter = [link.Link.make_link('self',
                                                    pecan.request.host_url,
                                                    'service_parameter', ''),
                                link.Link.make_link('bookmark',
                                                    pecan.request.host_url,
                                                    'service_parameter', '',
                                                    bookmark=True)
                                ]

        v1.clusters = [link.Link.make_link('self',
                                           pecan.request.host_url,
                                           'clusters', ''),
                       link.Link.make_link('bookmark',
                                           pecan.request.host_url,
                                           'clusters', '',
                                           bookmark=True)
                       ]

        v1.lldp_agents = [link.Link.make_link('self',
                                                    pecan.request.host_url,
                                                    'lldp_agents', ''),
                          link.Link.make_link('bookmark',
                                                    pecan.request.host_url,
                                                    'lldp_agents', '',
                                                    bookmark=True)
                          ]

        v1.lldp_neighbours = [link.Link.make_link('self',
                                                    pecan.request.host_url,
                                                    'lldp_neighbours', ''),
                              link.Link.make_link('bookmark',
                                                    pecan.request.host_url,
                                                    'lldp_neighbours', '',
                                                    bookmark=True)
                              ]

        # sm service
        v1.services = [link.Link.make_link('self',
                                           pecan.request.host_url,
                                           'services', ''),
                       link.Link.make_link('bookmark',
                                           pecan.request.host_url,
                                           'services', '',
                                           bookmark=True)
                       ]

        # sm service nodes
        v1.servicenodes = [link.Link.make_link('self',
                                               pecan.request.host_url,
                                               'servicenodes', ''),
                           link.Link.make_link('bookmark',
                                               pecan.request.host_url,
                                               'servicenodes', '',
                                               bookmark=True)
                           ]
        # sm service group
        v1.servicegroup = [link.Link.make_link('self',
                                               pecan.request.host_url,
                                               'servicegroup', ''),
                           link.Link.make_link('bookmark',
                                               pecan.request.host_url,
                                               'servicegroup', '',
                                               bookmark=True)
                           ]

        v1.health = [link.Link.make_link('self', pecan.request.host_url,
                                         'health', ''),
                     link.Link.make_link('bookmark', pecan.request.host_url,
                                         'health', '', bookmark=True)
                     ]

        v1.remotelogging = [link.Link.make_link('self',
                                                pecan.request.host_url,
                                                'remotelogging', ''),
                            link.Link.make_link('bookmark',
                                                pecan.request.host_url,
                                                'remotelogging', '',
                                                bookmark=True)
                            ]

        v1.sdn_controller = [link.Link.make_link('self',
                                                 pecan.request.host_url,
                                                 'sdn_controller', ''),
                             link.Link.make_link('bookmark',
                                                 pecan.request.host_url,
                                                 'sdn_controller', '',
                                                 bookmark=True)
                             ]

        v1.tpmconfig = [link.Link.make_link('self',
                                            pecan.request.host_url,
                                            'tpmconfig', ''),
                        link.Link.make_link('bookmark',
                                            pecan.request.host_url,
                                            'tpmconfig', '',
                                            bookmark=True)]

        v1.firewallrules = [link.Link.make_link('self',
                                                pecan.request.host_url,
                                                'firewallrules', ''),
                            link.Link.make_link('bookmark',
                                                pecan.request.host_url,
                                                'firewallrules', '',
                                                bookmark=True)]

        v1.license = [link.Link.make_link('self',
                                          pecan.request.host_url,
                                          'license', ''),
                      link.Link.make_link('bookmark',
                                          pecan.request.host_url,
                                          'license', '',
                                          bookmark=True)]

        return v1


class Controller(rest.RestController):
    """Version 1 API controller root."""

    isystems = system.SystemController()
    ihosts = host.HostController()
    inodes = node.NodeController()
    icpus = cpu.CPUController()
    imemorys = memory.MemoryController()
    iinterfaces = interface.InterfaceController()
    ports = port.PortController()
    ethernet_ports = ethernet_port.EthernetPortController()
    istors = storage.StorageController()
    ilvgs = lvg.LVGController()
    ipvs = pv.PVController()
    idisks = disk.DiskController()
    partitions = partition.PartitionController()
    iprofile = profile.ProfileController()
    itrapdest = trapdest.TrapDestController()
    icommunity = community.CommunityController()
    iuser = user.UserController()
    idns = dns.DNSController()
    intp = ntp.NTPController()
    iextoam = network_oam.OAMNetworkController()
    controller_fs = controller_fs.ControllerFsController()
    storage_backend = storage_backend.StorageBackendController()
    storage_lvm = storage_lvm.StorageLVMController()
    storage_file = storage_file.StorageFileController()
    storage_external = storage_external.StorageExternalController()
    storage_ceph = storage_ceph.StorageCephController()
    storage_tiers = storage_tier.StorageTierController()
    ceph_mon = ceph_mon.CephMonController()
    drbdconfig = drbdconfig.drbdconfigsController()
    ialarms = alarm.AlarmController()
    event_log = event_log.EventLogController()
    event_suppression = event_suppression.EventSuppressionController()
    iinfra = network_infra.InfraNetworkController()
    addresses = address.AddressController()
    addrpools = address_pool.AddressPoolController()
    routes = route.RouteController()
    certificate = certificate.CertificateController()
    isensors = sensor.SensorController()
    isensorgroups = sensorgroup.SensorGroupController()
    loads = load.LoadController()
    pci_devices = pci_device.PCIDeviceController()
    upgrade = upgrade.UpgradeController()
    networks = network.NetworkController()
    service_parameter = service_parameter.ServiceParameterController()
    clusters = cluster.ClusterController()
    lldp_agents = lldp_agent.LLDPAgentController()
    lldp_neighbours = lldp_neighbour.LLDPNeighbourController()
    services = service.SMServiceController()
    servicenodes = servicenode.SMServiceNodeController()
    servicegroup = servicegroup.SMServiceGroupController()
    health = health.HealthController()
    remotelogging = remotelogging.RemoteLoggingController()
    sdn_controller = sdn_controller.SDNControllerController()
    tpmconfig = tpmconfig.TPMConfigController()
    firewallrules = firewallrules.FirewallRulesController()
    license = license.LicenseController()

    @wsme_pecan.wsexpose(V1)
    def get(self):
        # NOTE: The reason why convert() it's being called for every
        #       request is because we need to get the host url from
        #       the request object to make the links.
        return V1.convert()


__all__ = (Controller)
