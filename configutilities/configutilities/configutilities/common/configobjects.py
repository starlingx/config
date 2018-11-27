"""
Copyright (c) 2015-2016 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

from netaddr import IPRange
from exceptions import ConfigFail, ValidateFail
from utils import is_mtu_valid, is_speed_valid, is_valid_vlan, \
    validate_network_str, validate_address_str

DEFAULT_CONFIG = 0
REGION_CONFIG = 1
SUBCLOUD_CONFIG = 2

MGMT_TYPE = 0
INFRA_TYPE = 1
OAM_TYPE = 2
NETWORK_PREFIX_NAMES = [
    ('MGMT', 'INFRA', 'OAM'),
    ('CLM', 'BLS', 'CAN')
]
LINK_SPEED_1G = 1000
LINK_SPEED_10G = 10000
LINK_SPEED_25G = 25000
VALID_LINK_SPEED = [LINK_SPEED_1G, LINK_SPEED_10G, LINK_SPEED_25G]

# Additions to this list must be reflected in the hostfile
# generator tool (config->configutilities->hostfiletool.py)
HOST_XML_ATTRIBUTES = ['hostname', 'personality', 'subfunctions',
                       'mgmt_mac', 'mgmt_ip',
                       'bm_ip', 'bm_type', 'bm_username',
                       'bm_password', 'boot_device', 'rootfs_device',
                       'install_output', 'console', 'vsc_controllers',
                       'power_on', 'location']

# Network naming types
DEFAULT_NAMES = 0
HP_NAMES = 1

# well-known default domain name
DEFAULT_DOMAIN_NAME = 'Default'


class LogicalInterface(object):
    """ Represents configuration for a logical interface.
    """
    def __init__(self):
        self.name = None
        self.mtu = None
        self.link_capacity = None
        self.lag_interface = False
        self.lag_mode = None
        self.ports = None

    def parse_config(self, system_config, logical_interface):
        # Ensure logical interface config is present
        if not system_config.has_section(logical_interface):
            raise ConfigFail("Missing config for logical interface %s." %
                             logical_interface)
        self.name = logical_interface

        # Parse/validate the MTU
        self.mtu = system_config.getint(logical_interface, 'INTERFACE_MTU')
        if not is_mtu_valid(self.mtu):
            raise ConfigFail("Invalid MTU value for %s. "
                             "Valid values: 576 - 9216" % logical_interface)

        # Parse/validate the link_capacity
        if system_config.has_option(logical_interface,
                                    'INTERFACE_LINK_CAPACITY'):
            self.link_capacity = \
                system_config.getint(logical_interface,
                                     'INTERFACE_LINK_CAPACITY')
        # link_capacity is optional
        if self.link_capacity:
            if not is_speed_valid(self.link_capacity,
                                  valid_speeds=VALID_LINK_SPEED):
                raise ConfigFail(
                    "Invalid link-capacity value for %s." % logical_interface)

        # Parse the ports
        self.ports = filter(None, [x.strip() for x in
                            system_config.get(logical_interface,
                                              'INTERFACE_PORTS').split(',')])

        # Parse/validate the LAG config
        lag_interface = system_config.get(logical_interface,
                                          'LAG_INTERFACE')
        if lag_interface.lower() == 'y':
            self.lag_interface = True
            if len(self.ports) != 2:
                raise ConfigFail(
                    "Invalid number of ports (%d) supplied for LAG "
                    "interface %s" % (len(self.ports), logical_interface))
            self.lag_mode = system_config.getint(logical_interface, 'LAG_MODE')
            if self.lag_mode < 1 or self.lag_mode > 6:
                raise ConfigFail(
                    "Invalid LAG_MODE value of %d for %s. Valid values: 1-6" %
                    (self.lag_mode, logical_interface))
        elif lag_interface.lower() == 'n':
            if len(self.ports) > 1:
                raise ConfigFail(
                    "More than one interface supplied for non-LAG "
                    "interface %s" % logical_interface)
            if len(self.ports) == 0:
                raise ConfigFail(
                    "No interfaces supplied for non-LAG "
                    "interface %s" % logical_interface)
        else:
            raise ConfigFail(
                "Invalid LAG_INTERFACE value of %s for %s. Valid values: "
                "Y or N" % (lag_interface, logical_interface))


class Network(object):
    """ Represents configuration for a network.
    """
    def __init__(self):
        self.vlan = None
        self.cidr = None
        self.multicast_cidr = None
        self.start_address = None
        self.end_address = None
        self.start_end_in_config = False
        self.floating_address = None
        self.address_0 = None
        self.address_1 = None
        self.dynamic_allocation = False
        self.gateway_address = None
        self.logical_interface = None

    def parse_config(self, system_config, config_type, network_type,
                     min_addresses=0, multicast_addresses=0, optional=False,
                     naming_type=DEFAULT_NAMES,
                     logical_interface_required=True):
        network_prefix = NETWORK_PREFIX_NAMES[naming_type][network_type]
        network_name = network_prefix + '_NETWORK'

        if naming_type == HP_NAMES:
            attr_prefix = network_prefix + '_'
        else:
            attr_prefix = ''

        # Ensure network config is present
        if not system_config.has_section(network_name):
            if not optional:
                raise ConfigFail("Missing config for network %s." %
                                 network_name)
            else:
                # Optional interface - just return
                return

        # Parse/validate the VLAN
        if system_config.has_option(network_name, attr_prefix + 'VLAN'):
            self.vlan = system_config.getint(network_name,
                                             attr_prefix + 'VLAN')
        if self.vlan:
            if not is_valid_vlan(self.vlan):
                raise ConfigFail(
                    "Invalid %s value of %d for %s. Valid values: 1-4094" %
                    (attr_prefix + 'VLAN', self.vlan, network_name))

        # Parse/validate the cidr
        cidr_str = system_config.get(network_name, attr_prefix + 'CIDR')
        try:
            self.cidr = validate_network_str(
                cidr_str, min_addresses)
        except ValidateFail as e:
            raise ConfigFail(
                "Invalid %s value of %s for %s.\nReason: %s" %
                (attr_prefix + 'CIDR', cidr_str, network_name, e))

        # Parse/validate the multicast subnet
        if 0 < multicast_addresses and \
                system_config.has_option(network_name,
                                         attr_prefix + 'MULTICAST_CIDR'):
            multicast_cidr_str = system_config.get(network_name, attr_prefix +
                                                   'MULTICAST_CIDR')
            try:
                self.multicast_cidr = validate_network_str(
                    multicast_cidr_str, multicast_addresses, multicast=True)
            except ValidateFail as e:
                raise ConfigFail(
                    "Invalid %s value of %s for %s.\nReason: %s" %
                    (attr_prefix + 'MULTICAST_CIDR', multicast_cidr_str,
                     network_name, e))

            if self.cidr.version != self.multicast_cidr.version:
                raise ConfigFail(
                    "Invalid %s value of %s for %s.  Multicast "
                    "subnet and network IP families must be the same." %
                    (attr_prefix + 'MULTICAST_CIDR', multicast_cidr_str,
                     network_name))

        # Parse/validate the hardwired controller addresses
        floating_address_str = None
        address_0_str = None
        address_1_str = None

        if min_addresses == 1:
            if (system_config.has_option(
                    network_name, attr_prefix + 'IP_FLOATING_ADDRESS') or
                system_config.has_option(
                    network_name, attr_prefix + 'IP_UNIT_0_ADDRESS') or
                system_config.has_option(
                    network_name, attr_prefix + 'IP_UNIT_1_ADDRESS') or
                system_config.has_option(
                    network_name, attr_prefix + 'IP_START_ADDRESS') or
                system_config.has_option(
                    network_name, attr_prefix + 'IP_END_ADDRESS')):
                raise ConfigFail(
                    "Only one IP address is required for OAM "
                    "network, use 'IP_ADDRESS' to specify the OAM IP "
                    "address")
            floating_address_str = system_config.get(
                network_name, attr_prefix + 'IP_ADDRESS')
            try:
                self.floating_address = validate_address_str(
                    floating_address_str, self.cidr)
            except ValidateFail as e:
                    raise ConfigFail(
                        "Invalid %s value of %s for %s.\nReason: %s" %
                        (attr_prefix + 'IP_ADDRESS',
                         floating_address_str, network_name, e))
            self.address_0 = self.floating_address
            self.address_1 = self.floating_address
        else:
            if system_config.has_option(
                    network_name, attr_prefix + 'IP_FLOATING_ADDRESS'):
                floating_address_str = system_config.get(
                    network_name, attr_prefix + 'IP_FLOATING_ADDRESS')
                try:
                    self.floating_address = validate_address_str(
                        floating_address_str, self.cidr)
                except ValidateFail as e:
                    raise ConfigFail(
                        "Invalid %s value of %s for %s.\nReason: %s" %
                        (attr_prefix + 'IP_FLOATING_ADDRESS',
                         floating_address_str, network_name, e))

            if system_config.has_option(
                    network_name, attr_prefix + 'IP_UNIT_0_ADDRESS'):
                address_0_str = system_config.get(
                    network_name, attr_prefix + 'IP_UNIT_0_ADDRESS')
                try:
                    self.address_0 = validate_address_str(
                        address_0_str, self.cidr)
                except ValidateFail as e:
                    raise ConfigFail(
                        "Invalid %s value of %s for %s.\nReason: %s" %
                        (attr_prefix + 'IP_UNIT_0_ADDRESS',
                         address_0_str, network_name, e))

            if system_config.has_option(
                    network_name, attr_prefix + 'IP_UNIT_1_ADDRESS'):
                address_1_str = system_config.get(
                    network_name, attr_prefix + 'IP_UNIT_1_ADDRESS')
                try:
                    self.address_1 = validate_address_str(
                        address_1_str, self.cidr)
                except ValidateFail as e:
                    raise ConfigFail(
                        "Invalid %s value of %s for %s.\nReason: %s" %
                        (attr_prefix + 'IP_UNIT_1_ADDRESS',
                         address_1_str, network_name, e))

            # Parse/validate the start/end addresses
            start_address_str = None
            end_address_str = None
            if system_config.has_option(
                    network_name, attr_prefix + 'IP_START_ADDRESS'):
                start_address_str = system_config.get(
                    network_name, attr_prefix + 'IP_START_ADDRESS')
                try:
                    self.start_address = validate_address_str(
                        start_address_str, self.cidr)
                except ValidateFail as e:
                    raise ConfigFail(
                        "Invalid %s value of %s for %s.\nReason: %s" %
                        (attr_prefix + 'IP_START_ADDRESS',
                         start_address_str, network_name, e))

            if system_config.has_option(
                    network_name, attr_prefix + 'IP_END_ADDRESS'):
                end_address_str = system_config.get(
                    network_name, attr_prefix + 'IP_END_ADDRESS')
                try:
                    self.end_address = validate_address_str(
                        end_address_str, self.cidr)
                except ValidateFail as e:
                    raise ConfigFail(
                        "Invalid %s value of %s for %s.\nReason: %s " %
                        (attr_prefix + 'IP_END_ADDRESS',
                         end_address_str, network_name, e))

            if start_address_str or end_address_str:
                if not end_address_str:
                    raise ConfigFail("Missing attribute %s for %s_NETWORK" %
                                     (attr_prefix + 'IP_END_ADDRESS',
                                      network_name))
                if not start_address_str:
                    raise ConfigFail("Missing attribute %s for %s_NETWORK" %
                                     (attr_prefix + 'IP_START_ADDRESS',
                                      network_name))
                if not self.start_address < self.end_address:
                    raise ConfigFail(
                        "Start address %s not less than end address %s for %s."
                        % (str(self.start_address), str(self.end_address),
                           network_name))
                if not IPRange(start_address_str, end_address_str).size >= \
                        min_addresses:
                    raise ConfigFail("Address range for %s must contain at "
                                     "least %d addresses." %
                                     (network_name, min_addresses))
                self.start_end_in_config = True

            if floating_address_str or address_0_str or address_1_str:
                if not floating_address_str:
                    raise ConfigFail("Missing attribute %s for %s_NETWORK" %
                                     (attr_prefix + 'IP_FLOATING_ADDRESS',
                                      network_name))
                if not address_0_str:
                    raise ConfigFail("Missing attribute %s for %s_NETWORK" %
                                     (attr_prefix + 'IP_UNIT_0_ADDRESS',
                                      network_name))
                if not address_1_str:
                    raise ConfigFail("Missing attribute %s for %s_NETWORK" %
                                     (attr_prefix + 'IP_UNIT_1_ADDRESS',
                                      network_name))

            if start_address_str and floating_address_str:
                    raise ConfigFail("Overspecified network: Can only set %s "
                                     "and %s OR %s, %s, and %s for "
                                     "%s_NETWORK" %
                                     (attr_prefix + 'IP_START_ADDRESS',
                                      attr_prefix + 'IP_END_ADDRESS',
                                      attr_prefix + 'IP_FLOATING_ADDRESS',
                                      attr_prefix + 'IP_UNIT_0_ADDRESS',
                                      attr_prefix + 'IP_UNIT_1_ADDRESS',
                                      network_name))

        if config_type == DEFAULT_CONFIG:
            if not self.start_address:
                self.start_address = self.cidr[2]
            if not self.end_address:
                self.end_address = self.cidr[-2]

        # Parse/validate the dynamic IP address allocation
        if system_config.has_option(network_name,
                                    'DYNAMIC_ALLOCATION'):
            dynamic_allocation = system_config.get(network_name,
                                                   'DYNAMIC_ALLOCATION')
            if dynamic_allocation.lower() == 'y':
                self.dynamic_allocation = True
            elif dynamic_allocation.lower() == 'n':
                self.dynamic_allocation = False
            else:
                raise ConfigFail(
                    "Invalid DYNAMIC_ALLOCATION value of %s for %s. "
                    "Valid values: Y or N" %
                    (dynamic_allocation, network_name))

        # Parse/validate the gateway (optional)
        if system_config.has_option(network_name, attr_prefix + 'GATEWAY'):
            gateway_address_str = system_config.get(
                network_name, attr_prefix + 'GATEWAY')
            try:
                self.gateway_address = validate_address_str(
                    gateway_address_str, self.cidr)
            except ValidateFail as e:
                raise ConfigFail(
                    "Invalid %s value of %s for %s.\nReason: %s" %
                    (attr_prefix + 'GATEWAY',
                     gateway_address_str, network_name, e))

        # Parse/validate the logical interface
        if logical_interface_required or system_config.has_option(
                network_name, attr_prefix + 'LOGICAL_INTERFACE'):
            logical_interface_name = system_config.get(
                network_name, attr_prefix + 'LOGICAL_INTERFACE')
            self.logical_interface = LogicalInterface()
            self.logical_interface.parse_config(system_config,
                                                logical_interface_name)
