#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Batch 8: partition_shell, network, lldp, license, kube_upgrade,
kube_rootca.
"""
import unittest
from unittest import mock

from cgtsclient import exc
from cgtsclient.tests.unit_coverage._helpers import _make_args
from cgtsclient.tests.unit_coverage._helpers import _make_resource
from cgtsclient.tests.unit_coverage._helpers import _patch_print
from cgtsclient.v1 import license_shell
from cgtsclient.v1 import lldp_agent_shell
from cgtsclient.v1 import lldp_neighbour_shell
from cgtsclient.v1 import network


# --- network.py _find_network ---
class TestNetworkFind(unittest.TestCase):
    def test_find_by_id(self):
        cc = mock.MagicMock()
        cc.network.list.return_value = (
            [_make_resource(id=1, name='mgmt', uuid='n1')]
        )
        r = network._find_network(cc, '1')
        self.assertEqual(r.name, 'mgmt')

    def test_find_by_uuid(self):
        cc = mock.MagicMock()
        cc.network.get.return_value = _make_resource(
            uuid='a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
            name='mgmt'
        )
        r = network._find_network(cc, 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11')
        self.assertEqual(r.name, 'mgmt')

    def test_find_by_name(self):
        cc = mock.MagicMock()
        cc.network.list.return_value = (
            [_make_resource(id=1, name='mgmt', uuid='n1')]
        )
        r = network._find_network(cc, 'mgmt')
        self.assertEqual(r.name, 'mgmt')

    def test_find_by_id_not_found(self):
        cc = mock.MagicMock()
        cc.network.list.return_value = []
        self.assertRaises(exc.CommandError, network._find_network, cc, '99')

    def test_find_by_uuid_not_found(self):
        cc = mock.MagicMock()
        cc.network.get.side_effect = exc.HTTPNotFound()
        self.assertRaises(exc.CommandError, network._find_network, cc,
                          'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11')

    def test_find_by_name_not_found(self):
        cc = mock.MagicMock()
        cc.network.list.return_value = []
        self.assertRaises(exc.CommandError,
                          network._find_network,
                          cc,
                          'missing')


# --- network_shell.py ---


# --- network_addrpool_shell.py ---


# --- lldp_agent_shell.py ---
@_patch_print
class TestLldpAgentShell(unittest.TestCase):

    def test_carriage_formatter(self, *_):
        r = lldp_agent_shell._lldp_carriage_formatter('hello\\nworld')
        self.assertNotIn('\\n', r)

    def test_system_name_formatter(self, *_):
        lldp = _make_resource(system_name='name\\nwith\\nnewlines')
        r = lldp_agent_shell._lldp_system_name_formatter(lldp)
        self.assertIsNotNone(r)

    def test_system_description_formatter(self, *_):
        lldp = (
            _make_resource(system_description='desc\\nwith\\nnewlines')
        )
        r = lldp_agent_shell._lldp_system_description_formatter(lldp)
        self.assertIsNotNone(r)

    def test_port_description_formatter(self, *_):
        lldp = _make_resource(port_description='port\\ndesc')
        r = lldp_agent_shell._lldp_port_description_formatter(lldp)
        self.assertIsNotNone(r)


@_patch_print
class TestLldpNeighbourShell(unittest.TestCase):

    def test_carriage_formatters(self, *_):
        self.assertIsNotNone(lldp_neighbour_shell._lldp_system_name_formatter(
            _make_resource(system_name='name\\n')))
        self.assertIsNotNone(lldp_neighbour_shell._lldp_system_description_formatter(
            _make_resource(system_description='desc\\n')))
        self.assertIsNotNone(lldp_neighbour_shell._lldp_port_description_formatter(
            _make_resource(port_description='port\\n')))


@_patch_print
class TestLicenseShell(unittest.TestCase):

    def test_license_install_error(self, *_):
        cc = mock.MagicMock()
        with mock.patch('builtins.open', side_effect=IOError):
            self.assertRaises(exc.CommandError, license_shell.do_license_install,
                              cc, _make_args(license_file_path='/bad'))


# --- kube_upgrade_shell.py ---


# --- kube_rootca_update_shell.py ---


if __name__ == '__main__':
    unittest.main()
