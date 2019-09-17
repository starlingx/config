"""
Copyright (c) 2014-2019 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

from six.moves import configparser
import mock
import os
import pytest
import sys

import controllerconfig.common.exceptions as exceptions
from controllerconfig import validate
from controllerconfig import DEFAULT_CONFIG

sys.modules['fm_core'] = mock.Mock()

import controllerconfig.systemconfig as cr  # noqa: E402


def _dump_config(config):
    """ Prints contents of config object """
    for section in config.sections():
        print("[%s]" % section)
        for (name, value) in config.items(section):
            print("%s=%s" % (name, value))


def _test_system_config(filename):
    """ Test import and generation of answerfile """

    # Parse the system_config file
    system_config = cr.parse_system_config(filename)

    # Dump results for debugging
    print("Parsed system_config:\n")
    _dump_config(system_config)

    # Validate the system config file
    cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                               validate_only=True)

    # Validate the system config file.
    # Using onboard validation since the validator's reference version number
    # is only set at build-time when validating offboard
    validate(system_config, DEFAULT_CONFIG, None, False)


def test_system_config_simple():
    """ Test import of simple system_config file """

    # Create the path to the system_config file
    systemfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/", "system_config.simple")

    _test_system_config(systemfile)


def test_system_config_ipv6():
    """ Test import of system_config file with ipv6 oam """

    # Create the path to the system_config file
    systemfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/", "system_config.ipv6")

    _test_system_config(systemfile)


def test_system_config_lag_vlan():
    """ Test import of system_config file with lag and vlan """

    # Create the path to the system_config file
    systemfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/", "system_config.lag.vlan")

    _test_system_config(systemfile)


def test_system_config_security():
    """ Test import of system_config file with security config """

    # Create the path to the system_config file
    systemfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/", "system_config.security")

    _test_system_config(systemfile)


def test_system_config_ceph():
    """ Test import of system_config file with ceph  config """

    # Create the path to the system_config file
    systemfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/", "system_config.ceph")

    _test_system_config(systemfile)


def test_system_config_simplex():
    """ Test import of system_config file for AIO-simplex """

    # Create the path to the system_config file
    systemfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/", "system_config.simplex")

    _test_system_config(systemfile)


def test_system_config_simplex_mgmt():
    """ Test import of system_config file for AIO-simplex with management
    configuration"""

    # Create the path to the system_config file
    systemfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/",
        "system_config.simplex_mgmt")

    _test_system_config(systemfile)

    # Test MGMT_NETWORK parameters that are not allowed
    system_config = cr.parse_system_config(systemfile)
    system_config.set('MGMT_NETWORK', 'GATEWAY', '192.168.42.1')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)
    system_config = cr.parse_system_config(systemfile)
    system_config.set('MGMT_NETWORK', 'LOGICAL_INTERFACE',
                      'LOGICAL_INTERFACE_1')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test overlap with OAM network
    system_config = cr.parse_system_config(systemfile)
    system_config.set('MGMT_NETWORK', 'CIDR', '10.10.10.0/24')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test IPv6 management CIDR (not supported)
    system_config = cr.parse_system_config(systemfile)
    system_config.set('MGMT_NETWORK', 'CIDR', 'FD01::0000/64')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test management CIDR that is too small
    system_config = cr.parse_system_config(systemfile)
    system_config.set('MGMT_NETWORK', 'CIDR', '192.168.42.0/29')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)


def test_system_config_validation():
    """ Test detection of various errors in system_config file """

    # Create the path to the system_config files
    simple_systemfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/", "system_config.simple")
    ipv6_systemfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/", "system_config.ipv6")
    lag_vlan_systemfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/", "system_config.lag.vlan")
    ceph_systemfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/", "system_config.ceph")
    static_addr_systemfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/",
        "system_config.static_addr")

    # Test floating outside of OAM_NETWORK CIDR
    system_config = cr.parse_system_config(ipv6_systemfile)
    system_config.set('OAM_NETWORK', 'IP_FLOATING_ADDRESS', '5555::5')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test non-ipv6 unit address
    system_config = cr.parse_system_config(ipv6_systemfile)
    system_config.set('OAM_NETWORK', 'IP_UNIT_0_ADDRESS', '10.10.10.3')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test missing pxeboot network when using IPv6 management network
    system_config = cr.parse_system_config(ipv6_systemfile)
    system_config.remove_section('PXEBOOT_NETWORK')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test ridiculously sized management network
    system_config = cr.parse_system_config(ipv6_systemfile)
    system_config.set('MGMT_NETWORK', 'IP_START_ADDRESS', '1234::b:0:0:0')
    system_config.set('MGMT_NETWORK', 'IP_END_ADDRESS',
                      '1234::b:ffff:ffff:ffff')
    system_config.remove_option('MGMT_NETWORK', 'IP_FLOATING_ADDRESS')
    system_config.remove_option('MGMT_NETWORK', 'IP_UNIT_0_ADDRESS')
    system_config.remove_option('MGMT_NETWORK', 'IP_UNIT_1_ADDRESS')
    cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                               validate_only=True)
    validate(system_config, DEFAULT_CONFIG, None, False)

    # Test using start/end addresses
    system_config = cr.parse_system_config(ipv6_systemfile)
    system_config.set('OAM_NETWORK', 'IP_START_ADDRESS', 'abcd::2')
    system_config.set('OAM_NETWORK', 'IP_END_ADDRESS', 'abcd::4')
    system_config.remove_option('OAM_NETWORK', 'IP_FLOATING_ADDRESS')
    system_config.remove_option('OAM_NETWORK', 'IP_UNIT_0_ADDRESS')
    system_config.remove_option('OAM_NETWORK', 'IP_UNIT_1_ADDRESS')
    cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                               validate_only=True)
    validate(system_config, DEFAULT_CONFIG, None, False)

    # Test detection of an invalid PXEBOOT_CIDR
    system_config = cr.parse_system_config(lag_vlan_systemfile)
    system_config.set('PXEBOOT_NETWORK', 'PXEBOOT_CIDR',
                      'FD00::0000/64')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    system_config.set('PXEBOOT_NETWORK', 'PXEBOOT_CIDR',
                      '192.168.1.0/29')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    system_config.remove_option('PXEBOOT_NETWORK', 'PXEBOOT_CIDR')
    with pytest.raises(configparser.NoOptionError):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(configparser.NoOptionError):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test overlap of MGMT_NETWORK CIDR
    system_config = cr.parse_system_config(lag_vlan_systemfile)
    system_config.set('MGMT_NETWORK', 'CIDR', '192.168.203.0/26')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test invalid MGMT_NETWORK LAG_MODE
    system_config = cr.parse_system_config(lag_vlan_systemfile)
    system_config.set('LOGICAL_INTERFACE_1', 'LAG_MODE', '2')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test MGMT_NETWORK VLAN not allowed
    system_config = cr.parse_system_config(simple_systemfile)
    system_config.set('MGMT_NETWORK', 'VLAN', '123')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test MGMT_NETWORK VLAN missing
    system_config = cr.parse_system_config(lag_vlan_systemfile)
    system_config.remove_option('MGMT_NETWORK', 'VLAN')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test MGMT_NETWORK start address specified without end address
    system_config = cr.parse_system_config(simple_systemfile)
    system_config.set('MGMT_NETWORK', 'IP_START_ADDRESS', '192.168.204.2')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test MGMT_NETWORK end address specified without start address
    system_config = cr.parse_system_config(simple_systemfile)
    system_config.set('MGMT_NETWORK', 'IP_END_ADDRESS', '192.168.204.200')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test MGMT_NETWORK start and end range does not have enough addresses
    system_config = cr.parse_system_config(static_addr_systemfile)
    system_config.set('MGMT_NETWORK', 'IP_START_ADDRESS', '192.168.204.2')
    system_config.set('MGMT_NETWORK', 'IP_END_ADDRESS', '192.168.204.8')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test MGMT_NETWORK start address not in subnet
    system_config = cr.parse_system_config(simple_systemfile)
    system_config.set('MGMT_NETWORK', 'IP_START_ADDRESS', '192.168.200.2')
    system_config.set('MGMT_NETWORK', 'IP_END_ADDRESS', '192.168.204.254')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test MGMT_NETWORK end address not in subnet
    system_config = cr.parse_system_config(simple_systemfile)
    system_config.set('MGMT_NETWORK', 'IP_START_ADDRESS', '192.168.204.2')
    system_config.set('MGMT_NETWORK', 'IP_END_ADDRESS', '192.168.214.254')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test overlap of CLUSTER_NETWORK CIDR
    system_config = cr.parse_system_config(lag_vlan_systemfile)
    system_config.set('CLUSTER_NETWORK', 'CIDR', '192.168.203.0/26')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    system_config.set('CLUSTER_NETWORK', 'CIDR', '192.168.204.0/26')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test invalid CLUSTER_NETWORK LAG_MODE
    system_config = cr.parse_system_config(lag_vlan_systemfile)
    system_config.add_section('LOGICAL_INTERFACE_2')
    system_config.set('LOGICAL_INTERFACE_2', 'LAG_INTERFACE', 'Y')
    system_config.set('LOGICAL_INTERFACE_2', 'LAG_MODE', '3')
    system_config.set('LOGICAL_INTERFACE_2', 'INTERFACE_MTU', '1500')
    system_config.set('LOGICAL_INTERFACE_2', 'INTERFACE_PORTS', 'eth3,eth4')
    system_config.set('CLUSTER_NETWORK', 'LOGICAL_INTERFACE',
                      'LOGICAL_INTERFACE_2')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test CLUSTER_NETWORK VLAN overlap
    system_config = cr.parse_system_config(lag_vlan_systemfile)
    system_config.set('CLUSTER_NETWORK', 'VLAN', '123')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test overlap of OAM_NETWORK CIDR
    system_config = cr.parse_system_config(lag_vlan_systemfile)
    system_config.set('OAM_NETWORK', 'CIDR', '192.168.203.0/26')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    system_config.set('OAM_NETWORK', 'CIDR', '192.168.204.0/26')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    system_config.set('OAM_NETWORK', 'CIDR', '192.168.205.0/26')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test invalid OAM_NETWORK LAG_MODE
    system_config = cr.parse_system_config(lag_vlan_systemfile)
    system_config.add_section('LOGICAL_INTERFACE_2')
    system_config.set('LOGICAL_INTERFACE_2', 'LAG_INTERFACE', 'Y')
    system_config.set('LOGICAL_INTERFACE_2', 'LAG_MODE', '3')
    system_config.set('LOGICAL_INTERFACE_2', 'INTERFACE_MTU', '1500')
    system_config.set('LOGICAL_INTERFACE_2', 'INTERFACE_PORTS', 'eth3,eth4')
    system_config.set('OAM_NETWORK', 'LOGICAL_INTERFACE',
                      'LOGICAL_INTERFACE_2')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test OAM_NETWORK VLAN overlap
    system_config = cr.parse_system_config(lag_vlan_systemfile)
    system_config.set('OAM_NETWORK', 'VLAN', '123')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    system_config.set('OAM_NETWORK', 'VLAN', '126')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test OAM_NETWORK VLAN missing
    system_config = cr.parse_system_config(lag_vlan_systemfile)
    system_config.remove_option('OAM_NETWORK', 'VLAN')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test missing gateway
    system_config = cr.parse_system_config(lag_vlan_systemfile)
    system_config.remove_option('MGMT_NETWORK', 'GATEWAY')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test two gateways
    system_config = cr.parse_system_config(lag_vlan_systemfile)
    system_config.set('OAM_NETWORK', 'GATEWAY', '10.10.10.1')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test detection of unsupported NTP NTP_SERVER
    system_config = cr.parse_system_config(simple_systemfile)
    system_config.add_section('NTP')
    system_config.set('NTP', 'NTP_SERVER_1', '0.pool.ntp.org')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)

    # Test detection of overspecification of MGMT network addresses
    system_config = cr.parse_system_config(ceph_systemfile)
    system_config.set('MGMT_NETWORK', 'IP_FLOATING_ADDRESS', '192.168.204.3')
    system_config.set('MGMT_NETWORK', 'IP_IP_UNIT_0_ADDRESS', '192.168.204.6')
    system_config.set('MGMT_NETWORK', 'IP_IP_UNIT_1_ADDRESS', '192.168.204.9')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)

    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test detection of overspecification of OAM network addresses
    system_config = cr.parse_system_config(ceph_systemfile)
    system_config.set('MGMT_NETWORK', 'IP_FLOATING_ADDRESS', '10.10.10.2')
    system_config.set('MGMT_NETWORK', 'IP_IP_UNIT_0_ADDRESS', '10.10.10.3')
    system_config.set('MGMT_NETWORK', 'IP_IP_UNIT_1_ADDRESS', '10.10.10.4')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test detection of invalid release version
    system_config = cr.parse_system_config(ceph_systemfile)
    system_config.set('VERSION', 'RELEASE', '15.12')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)


def test_pxeboot_range():
    """ Test import of system_config file for PXEBoot network address """

    # Create the path to the system_config file
    systemfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/", "system_config.pxeboot")

    # Test import and generation of answer file
    _test_system_config(systemfile)

    # Test detection of invalid PXEBoot network start address
    system_config = cr.parse_system_config(systemfile)
    system_config.set('PXEBOOT_NETWORK', 'IP_START_ADDRESS', '8.123.122.345')
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test detection of invalid PXEBoot network end address
    system_config = cr.parse_system_config(systemfile)
    system_config.set('PXEBOOT_NETWORK', 'IP_END_ADDRESS', '128.123.122.345')
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test detection of smaller PXEBoot network end address
    system_config = cr.parse_system_config(systemfile)
    system_config.set('PXEBOOT_NETWORK', 'IP_END_ADDRESS', '192.168.102.30')
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test detection of PXEBoot network range less than min required (8)
    system_config = cr.parse_system_config(systemfile)
    system_config.set('PXEBOOT_NETWORK', 'IP_END_ADDRESS', '128.123.122.34')
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)


def test_kubernetes():
    """ Test import of system_config file for kubernetes """

    # Create the path to the system_config file
    systemfile = os.path.join(
        os.getcwd(), "controllerconfig/tests/files/",
        "system_config.kubernetes")

    # Test import and generation of answer file
    _test_system_config(systemfile)

    # Test CLUSTER_NETWORK start address specified without end address
    system_config = cr.parse_system_config(systemfile)
    system_config.set('CLUSTER_NETWORK', 'IP_START_ADDRESS', '192.168.204.2')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test CLUSTER_NETWORK end address specified without start address
    system_config = cr.parse_system_config(systemfile)
    system_config.set('CLUSTER_NETWORK', 'IP_END_ADDRESS', '192.168.204.200')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test detection of overspecification of CLUSTER network addresses
    system_config = cr.parse_system_config(systemfile)
    system_config.set('CLUSTER_NETWORK', 'IP_FLOATING_ADDRESS',
                      '192.168.206.103')
    system_config.set('CLUSTER_NETWORK', 'IP_IP_UNIT_0_ADDRESS',
                      '192.168.206.106')
    system_config.set('CLUSTER_NETWORK', 'IP_IP_UNIT_1_ADDRESS',
                      '192.168.206.109')
    with pytest.raises(exceptions.ConfigFail):
        cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                                   validate_only=True)
    with pytest.raises(exceptions.ConfigFail):
        validate(system_config, DEFAULT_CONFIG, None, False)

    # Test absence of optional DNS configuration
    system_config = cr.parse_system_config(systemfile)
    system_config.remove_section('DNS')
    cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                               validate_only=True)
    validate(system_config, DEFAULT_CONFIG, None, False)

    # Test absence of optional docker proxy configuration
    system_config = cr.parse_system_config(systemfile)
    system_config.remove_section('DOCKER_PROXY')
    cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                               validate_only=True)
    validate(system_config, DEFAULT_CONFIG, None, False)

    # Test absence of optional docker registry configuration
    system_config = cr.parse_system_config(systemfile)
    system_config.remove_section('DOCKER_REGISTRY')
    cr.create_cgcs_config_file(None, system_config, None, None, None, 0,
                               validate_only=True)
    validate(system_config, DEFAULT_CONFIG, None, False)
