# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json
import re
import uuid

from sysinv.common import constants
from sysinv.puppet import interface
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils
from sysinv.tests.puppet import test_interface


class SriovdpTestCase(test_interface.InterfaceTestCaseMixin, dbbase.BaseHostTestCase):

    def setUp(self):
        super(SriovdpTestCase, self).setUp()
        self._setup_context()

    def _setup_configuration(self):
        # Create a host with the sriovdp=enabled label assigned
        self.host = self._create_test_host(constants.WORKER)
        sriovdp_key = constants.SRIOVDP_LABEL.split('=')[0]
        sriovdp_val = constants.SRIOVDP_LABEL.split('=')[1]
        dbutils.create_test_label(
                    host_id=self.host.id,
                    label_key=sriovdp_key,
                    label_value=sriovdp_val)

        # Setup a single port/SR-IOV interface
        self.port, self.iface = self._create_ethernet_test(
            'sriov1', constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV, sriov_numvfs=2,
            sriov_vf_driver='ixgbevf')

        # Create a datanetwork and assign the interface to it
        dn_values = {
            'name': 'group0-data0',
            'uuid': str(uuid.uuid4()),
            'network_type': constants.DATANETWORK_TYPE_VLAN,
            'mtu': 1500
        }
        self.datanetwork = dbutils.create_test_datanetwork(**dn_values)
        dbutils.create_test_interface_datanetwork(
            interface_id=self.iface.id, datanetwork_id=self.datanetwork.id)

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.
        self.port.save(self.admin_context)
        self.iface.save(self.admin_context)
        super(SriovdpTestCase, self)._update_context()

    def _get_pcidp_vendor_id(self, port):
        vendor = None
        # The vendor id can be found by inspecting the '[xxxx]' at the
        # end of the port's pvendor field
        vendor = re.search(r'\[([0-9a-fA-F]{1,4})\]$', port['pvendor'])
        if vendor:
            vendor = vendor.group(1)
        return vendor

    def _update_sriov_port_config(self, config):
        # Update the SR-IOV port config with NIC specific information
        self.port['pvendor'] = config['pf_vendor']
        self.port['pdevice'] = config['pf_device']
        self.port['driver'] = config['pf_driver']
        self.port['sriov_vf_driver'] = config['vf_driver']
        self.port['sriov_vf_pdevice_id'] = config['vf_device']
        self._update_context()

    def _generate_sriovdp_config(self):
        return self.operator.kubernetes._get_host_pcidp_config(self.host)  # pylint: disable=no-member

    def _get_sriovdp_config(self, datanetwork, vf_vendor, vf_device,
                            vf_driver, pfName):
        datanetwork = datanetwork.replace("-", "_")
        sriovdp_config = {
            "resourceList": [
                {
                    "resourceName": 'pci_sriov_net_{}'.format(datanetwork),
                    "selectors": {
                        "vendors": ["{}".format(vf_vendor)],
                        "devices": ["{}".format(vf_device)],
                        "drivers": ["{}".format(vf_driver)],
                        "pfNames": ["{}".format(pfName)]
                    }
                }
            ]
        }

        if interface.is_a_mellanox_device(self.context, self.iface):
            sriovdp_config['resourceList'][0]['selectors']['isRdma'] = True

        config = {
            "platform::kubernetes::worker::pci::pcidp_network_resources":
                json.dumps(sriovdp_config)
        }
        return config

    def test_generate_sriovdp_config_8086(self):

        test_config = {
            'pf_vendor': 'Intel Corporation [8086]',
            'pf_device': '10fd',
            'pf_driver': 'ixgbe',
            'vf_device': '10ed',
            'vf_driver': 'ixgbevf'
        }
        self._update_sriov_port_config(test_config)

        actual = self._generate_sriovdp_config()
        expected = self._get_sriovdp_config(
            self.datanetwork['name'],
            self._get_pcidp_vendor_id(self.port),
            test_config['vf_device'],
            test_config['vf_driver'],
            self.port['name']
        )
        self.assertEqual(expected, actual)

    def test_generate_sriovdp_config_mlx(self):

        test_config = {
            'pf_vendor': 'Mellanox Technologies [15b3]',
            'pf_device': '1015',
            'pf_driver': 'mlx5_core',
            'vf_device': '1016',
            'vf_driver': 'mlx5_core'
        }
        self._update_sriov_port_config(test_config)

        actual = self._generate_sriovdp_config()
        expected = self._get_sriovdp_config(
            self.datanetwork['name'],
            self._get_pcidp_vendor_id(self.port),
            test_config['vf_device'],
            test_config['vf_driver'],
            self.port['name']
        )
        self.assertEqual(expected, actual)

    def test_generate_sriovdp_config_invalid(self):

        self.iface['ifclass'] = constants.INTERFACE_CLASS_DATA
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self._update_context()

        actual = self._generate_sriovdp_config()
        expected = {
            "platform::kubernetes::worker::pci::pcidp_network_resources":
                json.dumps({"resourceList": []})
        }
        self.assertEqual(expected, actual)
