# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# Copyright 2013 Hewlett-Packard Development Company, L.P.
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
# Copyright (c) 2013-2015 Wind River Systems, Inc.
#


import netaddr
from sysinv.common import constants
from sysinv.openstack.common import log
from sysinv.openstack.common.gettextutils import _

LOG = log.getLogger(__name__)


class InvalidProfileData(Exception):
    pass


class Network(object):
    def __init__(self, node, networkType):
        self.networkType = networkType
        self.providerNetworks = []

        providerNetworksNode = node.find('providerNetworks')
        if providerNetworksNode:
            for pnetNode in providerNetworksNode.findall('providerNetwork'):
                pnetName = pnetNode.get('name')
                self.addProviderNetwork(pnetName)

    def addProviderNetwork(self, pnet):
        if pnet not in self.providerNetworks:
            self.providerNetworks.append(pnet)
        # ignore if provider network is duplicated within one interface

    def validate(self):
        if len(self.providerNetworks) == 0:
            # caller will do the translation
            raise InvalidProfileData("At least one provider network must be selected.")


class DataclassNetwork(Network):
    def __init__(self, node):

        super(DataclassNetwork, self).__init__(node, constants.NETWORK_TYPE_DATA)
        self.ipv4Mode = DataclassNetwork.getIpMode(node, "ipv4")
        self.ipv6Mode = DataclassNetwork.getIpMode(node, "ipv6")
        self.routes = DataclassNetwork.getRoutes(node)

    @staticmethod
    def getRoutes(node):
        routesNode = node.find('routes')
        if routesNode is None:
            return []

        routes = []
        for routeNode in routesNode.findall('route'):
            route = {}
            route['metric'] = int(routeNode.get('metric'))
            network = routeNode.get('network')
            gateway = routeNode.get('gateway')

            try:
                addr = netaddr.IPAddress(gateway)
            except netaddr.core.AddrFormatError:
                raise InvalidProfileData(_('%s is not a valid IP address') % gateway)

            try:
                net = netaddr.IPNetwork(network)
            except netaddr.core.AddrFormatError:
                raise InvalidProfileData(_('%s is not a valid network') % network)

            if addr.format() != gateway:
                raise InvalidProfileData(_('%s is not a valid IP address') % gateway)

            if net.version != addr.version:
                raise InvalidProfileData(_('network "%s" and gateway "%s" must be the same version.') %
                                         (network, gateway))

            route['network'] = net.network.format()
            route['prefix'] = net.prefixlen
            route['gateway'] = gateway
            route['family'] = net.version

            routes.append(route)
        return routes

    @staticmethod
    def getIpMode(node, name):
        modeNode = node.find(name)
        if modeNode is None:
            raise InvalidProfileData(_('%s is required for a datanetwork') % name)

        mode = modeNode.get('mode')
        pool = None
        if mode == 'pool':
            poolNode = modeNode.find('pool')
            if poolNode is None:
                raise InvalidProfileData(_('A pool is required for a %s defined as "pool"') % name)

            pool = poolNode.get('name')

        return {'mode': mode, 'pool': pool}


class ExternalNetwork(object):
    def __init__(self, node, networktype):
        self.networkType = networktype

    def validate(self):
        pass


class PciPassthrough(Network):
    def __init__(self, node):
        super(PciPassthrough, self).__init__(node, constants.NETWORK_TYPE_PCI_PASSTHROUGH)


class PciSriov(Network):
    def __init__(self, node):
        super(PciSriov, self).__init__(node, constants.NETWORK_TYPE_PCI_SRIOV)
        self.virtualFunctions = int(node.get('virtualFunctions'))


class Interface(object):
    def __init__(self, ifNode):

        self.providerNetworks = []
        self.networks = []
        self.name = ifNode.get('ifName')
        self.mtu = ifNode.get('mtu')
        self.ipv4Mode = {'mode': None, 'pool': None}
        self.ipv6Mode = {'mode': None, 'pool': None}
        self.routes = []
        self.virtualFunctions = 0
        networksNode = ifNode.find('networks')
        if networksNode is not None:
            for netNode in networksNode:
                self.addNetwork(netNode)

    def getNetworkMap(self):
        return {}

    def addNetwork(self, node):
        tag = node.tag
        networkMap = self.getNetworkMap()
        if tag in networkMap:
            network = networkMap[tag](node)
            self.networks.append(network)
            if network.networkType == constants.NETWORK_TYPE_DATA:
                self.ipv4Mode = network.ipv4Mode
                self.ipv6Mode = network.ipv6Mode
                self.routes = network.routes
            elif network.networkType == constants.NETWORK_TYPE_PCI_SRIOV:
                self.virtualFunctions = network.virtualFunctions

            if isinstance(network, Network):
                self.providerNetworks = network.providerNetworks

        else:
            raise InvalidProfileData(_('network type (%s) not recognizable') % tag)

    def validate(self):
        # raise InvalidProfileData exception with detail msg
        numberOfNetworks = len(self.networks)

        if numberOfNetworks > 2:
            raise InvalidProfileData(_('Too many network types selected for the interface.'))

        # when change, make sure modify the displayText as well
        combineTypes = [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_CLUSTER_HOST]
        displayText = _('Only mgmt and cluster-host network types can be combined on a single interface')
        if numberOfNetworks == 2:
            if self.networks[0].networkType not in combineTypes or \
                    self.networks[1].networkType not in combineTypes:
                raise InvalidProfileData(displayText)

            if self.networks[0].networkType == self.networks[1].networkType:
                raise InvalidProfileData(_('Interface can not combine with 2 networks with the same type.'))

        try:
            for network in self.networks:
                network.validate()
        except InvalidProfileData as e:
            raise InvalidProfileData(_(e.message + ' Interface: %s') % self.name)

    def getNetworks(self):
        pnets = ''
        networkTypes = ''
        hasNT = False
        for network in self.networks:
            if network.networkType is None:
                continue

            hasNT = True
            if networkTypes:
                networkTypes += ','
            networkTypes = networkTypes + network.networkType
            if hasattr(network, 'providerNetworks'):
                # there should be only one network has providerNetwork
                for pnet in network.providerNetworks:
                    if pnets:
                        pnets += ','
                    pnets = pnets + pnet

        if not hasNT:
            networkTypes = None
            pnets = None

        return networkTypes, pnets


class EthInterface(Interface):
    def __init__(self, ifNode):
        super(EthInterface, self).__init__(ifNode)
        self.port, self.pciAddress, self.pclass, self.pdevice = self.getPort(ifNode)

    def getPort(self, ifNode):
        portNode = ifNode.find('port')
        if portNode is None:
            raise InvalidProfileData(_('Ethernet interface %s requires an Ethernet port ') %
                                     ifNode.get('ifName'))

        pciAddress = ''
        tmp = portNode.get('pciAddress')
        try:
            pciAddress = EthInterface.formatPciAddress(tmp)
        except InvalidProfileData as exc:
            raise InvalidProfileData(exc.message + _('Interface %s, pciAddress %s') % (ifNode.get('ifName'), tmp))

        pclass = portNode.get('class')
        if pclass:
            pclass = pclass.strip()

        pdevice = portNode.get('device')
        if pdevice:
            pdevice = pdevice.strip()

        return portNode.get('name'), pciAddress, pclass, pdevice

    @staticmethod
    def formatPciAddress(value):
        # To parse a [X]:[X]:[X].[X] formatted pci address into [04x]:[02x]:[02x].[01x] pci address format
        if value:
            section_list1 = value.split(':')
        else:
            return ''

        if len(section_list1) != 3:
            raise InvalidProfileData(_('pciAddress is not well formatted.'))

        section_list2 = section_list1[2].split('.')
        if len(section_list2) != 2:
            raise InvalidProfileData(_('pciAddress is not well formatted.'))

        try:
            sec1 = int(section_list1[0], 16)
            sec2 = int(section_list1[1], 16)
            sec3 = int(section_list2[0], 16)
            sec4 = int(section_list2[1], 16)
        except (TypeError, ValueError):
            raise InvalidProfileData(_('pciAddress is not well formatted.'))

        result = '{0:04x}:{1:02x}:{2:02x}.{3:01x}'.format(sec1, sec2, sec3, sec4)

        return result

    def getNetworkMap(self):
        return {
                    'dataclassNetwork': lambda node: DataclassNetwork(node),
                    'clusterhostNetwork': lambda node: ExternalNetwork(node, constants.NETWORK_TYPE_CLUSTER_HOST),
                    'oamNetwork': lambda node: ExternalNetwork(node, constants.NETWORK_TYPE_OAM),
                    'mgmtNetwork': lambda node: ExternalNetwork(node, constants.NETWORK_TYPE_MGMT),
                    'pciPassthrough': lambda node: PciPassthrough(node),
                    'pciSriov': lambda node: PciSriov(node)
                 }


class AeInterface(Interface):
    def __init__(self, ifNode):
        super(AeInterface, self).__init__(ifNode)
        self.usesIf = []
        aeModeNode = ifNode.find('aeMode')  # aeMode is mandatory required by schema
        node = aeModeNode[0]  # it is mandatory required by schema

        if node.tag == 'activeStandby':
            self.aeMode = 'activeStandby'
            self.txPolicy = None
        elif node.tag == 'balanced':
            self.aeMode = 'balanced'
            self.txPolicy = node.get('txPolicy')
        elif node.tag == 'ieee802.3ad':
            self.aeMode = '802.3ad'
            self.txPolicy = node.get('txPolicy')

        node = ifNode.find('interfaces')
        if node:
            for usesIfNode in node.findall('interface'):
                self.addUsesIf(usesIfNode.get('name'))

    def addUsesIf(self, ifName):
        if not ifName:
            raise InvalidProfileData(_('Interface name value cannot be empty.'))
        if ifName == self.name:
            raise InvalidProfileData(_('Aggregrated ethernet interface (%s) cannot use itself.') % self.name)

        if ifName not in self.usesIf:
            self.usesIf.append(ifName)

    def getNetworkMap(self):
        return {
                    'dataclassNetwork': lambda node: DataclassNetwork(node),
                    'clusterhostNetwork': lambda node: ExternalNetwork(node, constants.NETWORK_TYPE_CLUSTER_HOST),
                    'oamNetwork': lambda node: ExternalNetwork(node, constants.NETWORK_TYPE_OAM),
                    'mgmtNetwork': lambda node: ExternalNetwork(node, constants.NETWORK_TYPE_MGMT)
                 }

    def validateWithIfNames(self, allInterfaceNames):
        # raise InvalidProfileData exception if invalid
        if len(self.usesIf) == 0:
            msg = _('Aggregrated ethernet interface (%s) should have at least one interface.') % self.name
            raise InvalidProfileData(msg)

        for usesIfName in self.usesIf:
            if usesIfName not in allInterfaceNames:
                msg = _('Aggregrated ethernet interface (%s) uses a undeclared interface (%s)') % \
                                         (self.name, usesIfName)
                raise InvalidProfileData(msg)
        super(AeInterface, self).validate()


class VlanInterface(Interface):
    def __init__(self, ifNode):
        super(VlanInterface, self).__init__(ifNode)
        self.vlanId = int(ifNode.get('vlanId'))
        usesIf = ifNode.get('interface')

        if not usesIf:
            raise InvalidProfileData(_('<usesIf> value cannot be empty.'))
        if usesIf == self.name:
            raise InvalidProfileData(_('vlan interface (%s) cannot use itself.') % self.name)
        self.usesIfName = usesIf
        self.usesIf = [usesIf]

    def getNetworkMap(self):
        return {
                'dataclassNetwork': lambda node: DataclassNetwork(node),
                'clusterhostNetwork': lambda node: ExternalNetwork(node, constants.NETWORK_TYPE_CLUSTER_HOST),
                'oamNetwork': lambda node: ExternalNetwork(node, constants.NETWORK_TYPE_OAM),
                'mgmtNetwork': lambda node: ExternalNetwork(node, constants.NETWORK_TYPE_MGMT)
        }

    @staticmethod
    def isEthInterface(ifName, ethIfMap):
        return ifName in ethIfMap

    def validateWithIfNames(self, allInterfaceNames, aeIfMap, vlanIfMap, ethIfMap):
        #  raise InvalidProfileData exception if invalid
        if self.usesIfName not in allInterfaceNames:
            msg = _('vlan interface (%s) uses a undeclared interface (%s)') % \
                                     (self.name, self.usesIfName)
            raise InvalidProfileData(msg)

        isEthIf = self.isEthInterface(self.usesIfName, ethIfMap)

        good = True
        if not isEthIf:
            ifNameToCheck = [self.usesIfName]

            while len(ifNameToCheck) > 0:
                ifName = ifNameToCheck.pop(0)
                if ifName in aeIfMap:
                    aeIf = aeIfMap[ifName]
                    for n in aeIf.usesIf:
                        ifNameToCheck.append(n)
                elif ifName in vlanIfMap:
                    good = False
                    break  # not good,a vlan in uses tree

        if not good:
            raise InvalidProfileData(_('A vlan interface cannot use a vlan interface.'))

        super(VlanInterface, self).validate()
