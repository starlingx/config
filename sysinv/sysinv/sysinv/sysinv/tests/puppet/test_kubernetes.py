# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json
import mock
import re
import uuid

from sysinv.common import utils
from sysinv.common import constants
from sysinv.common import device as dconstants
from sysinv.common import kubernetes
from sysinv.puppet import interface
from sysinv.puppet import puppet
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils
from sysinv.tests.puppet import base
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
        self.port = None
        self.iface = None
        self.device = None

    def _setup_iface_configuration(self):
        # Setup a single port/SR-IOV interface
        self.port, self.iface = self._create_ethernet_test(
            'sriov1', constants.INTERFACE_CLASS_PCI_SRIOV,
            constants.NETWORK_TYPE_PCI_SRIOV, sriov_numvfs=2,
            sriov_vf_driver='ixgbevf',
            sriov_vfs_pci_address="0000:b1:02.0,0000:b1:02.1")

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

    def _setup_fpga_configuration(self):
        # Setup a single FPGA FEC device
        self.device = dbutils.create_test_pci_device(
            host_id=self.host.id,
            pclass_id='030000',
            pvendor_id='80ee',
            pdevice_id='beef',
            sriov_totalvfs=64
        )

    def _update_context(self):
        # ensure DB entries are updated prior to updating the context which
        # will re-read the entries from the DB.
        if self.port:
            self.port.save(self.admin_context)
        if self.iface:
            self.iface.save(self.admin_context)
        if self.device:
            self.device.save(self.admin_context)
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

    def _update_sriov_fpga_config(self, config):
        # Update the SR-IOV port config with NIC specific information
        self.device['pclass_id'] = config['pf_class_id']
        self.device['pvendor_id'] = config['pf_vendor_id']
        self.device['pdevice_id'] = config['pf_device_id']
        self.device['driver'] = config['pf_driver']
        self.device['sriov_vf_driver'] = config['vf_driver']
        self.device['sriov_vf_pdevice_id'] = config['vf_device_id']
        self._update_context()

    def _get_sriovdp_fpga_config(self, vf_vendor, vf_device,
                                 vf_driver):
        name = "intel_fpga_fec"
        config = [{
            "resourceName": name,
            "deviceType": "accelerator",
            "selectors": {
                "vendors": ["{}".format(vf_vendor)],
                "devices": ["{}".format(vf_device)],
                "drivers": ["{}".format(vf_driver)]
            }
        }]

        return config

    def _get_sriovdp_iface_config(self, vf_vendor, vf_device,
                                  vf_driver, pfName, datanetwork):
        datanetwork = datanetwork.replace("-", "_")
        config = [{
            "resourceName": 'pci_sriov_net_{}'.format(datanetwork),
            "selectors": {
                "vendors": ["{}".format(vf_vendor)],
                "devices": ["{}".format(vf_device)],
                "drivers": ["{}".format(vf_driver)],
                "pfNames": ["{}".format(pfName)]
            }
        }]
        if interface.is_a_mellanox_device(self.context, self.iface):
            config[0]['selectors']['isRdma'] = True
        return config

    def _generate_sriovdp_config(self):
        return self.operator.kubernetes._get_host_pcidp_config(self.host)  # pylint: disable=no-member

    def _get_sriovdp_config(self, vf_vendor, vf_device,
                            vf_driver, pfName=None, datanetwork=None):

        iface_config = []
        if datanetwork:
            iface_config = self._get_sriovdp_iface_config(
                vf_vendor, vf_device, vf_driver, pfName, datanetwork)

        fpga_config = []
        if vf_device == dconstants.PCI_DEVICE_ID_FPGA_INTEL_5GNR_FEC_VF:
            fpga_config = self._get_sriovdp_fpga_config(
                vf_vendor, vf_device, vf_driver)

        config = {
            "platform::kubernetes::worker::pci::pcidp_resources":
                json.dumps({'resourceList': iface_config + fpga_config})
        }
        return config

    @mock.patch.object(utils, 'get_sriov_vf_index')
    def test_generate_sriovdp_config_8086(self, mock_get_sriov_vf_index):
        mock_get_sriov_vf_index.side_effect = [1, 2]
        self._setup_iface_configuration()
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
            self._get_pcidp_vendor_id(self.port),
            test_config['vf_device'],
            test_config['vf_driver'],
            pfName="%s#1,2" % self.port['name'],
            datanetwork=self.datanetwork['name']
        )
        mock_get_sriov_vf_index.assert_called()
        self.assertEqual(expected, actual)

    @mock.patch.object(utils, 'get_sriov_vf_index')
    def test_generate_sriovdp_config_mlx(self, mock_get_sriov_vf_index):
        mock_get_sriov_vf_index.side_effect = [1, 2]
        self._setup_iface_configuration()
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
            self._get_pcidp_vendor_id(self.port),
            test_config['vf_device'],
            test_config['vf_driver'],
            pfName="%s#1,2" % self.port['name'],
            datanetwork=self.datanetwork['name']
        )
        self.assertEqual(expected, actual)

    def test_generate_sriovdp_config_invalid(self):

        self._setup_iface_configuration()
        self.iface['ifclass'] = constants.INTERFACE_CLASS_DATA
        self.iface['networktype'] = constants.NETWORK_TYPE_DATA
        self._update_context()

        actual = self._generate_sriovdp_config()
        expected = {
            "platform::kubernetes::worker::pci::pcidp_resources":
                json.dumps({"resourceList": []})
        }
        self.assertEqual(expected, actual)

    def test_generate_sriovdp_config_fpga_fec(self):

        self._setup_fpga_configuration()
        test_config = {
            'pf_class_id': dconstants.PCI_DEVICE_CLASS_FPGA,
            'pf_vendor_id': dconstants.PCI_DEVICE_VENDOR_INTEL,
            'pf_device_id': dconstants.PCI_DEVICE_ID_FPGA_INTEL_5GNR_FEC_PF,
            'pf_driver': 'igb_uio',
            'vf_device_id': dconstants.PCI_DEVICE_ID_FPGA_INTEL_5GNR_FEC_VF,
            'vf_driver': 'igb_uio'
        }
        self._update_sriov_fpga_config(test_config)

        actual = self._generate_sriovdp_config()
        expected = self._get_sriovdp_config(
            test_config['pf_vendor_id'],
            test_config['vf_device_id'],
            test_config['vf_driver']
        )
        self.assertEqual(expected, actual)

    def test_generate_sriovdp_config_fpga_unsupported(self):

        self._setup_fpga_configuration()
        test_config = {
            'pf_class_id': 'AAAA',
            'pf_vendor_id': 'BBBB',
            'pf_device_id': 'CCCC',
            'pf_driver': 'igb_uio',
            'vf_device_id': 'DDDD',
            'vf_driver': 'igb_uio'
        }
        self._update_sriov_fpga_config(test_config)

        actual = self._generate_sriovdp_config()
        expected = {
            "platform::kubernetes::worker::pci::pcidp_resources":
                json.dumps({'resourceList': []})
        }
        self.assertEqual(expected, actual)


class KubeVersionTestCase(base.PuppetTestCaseMixin, dbbase.BaseHostTestCase):

    def setUp(self):
        super(KubeVersionTestCase, self).setUp()

        # Create a host
        self.host = self._create_test_host(constants.WORKER)

        self._update_context()

    @puppet.puppet_context
    def _update_context(self):
        self.context = {}

    def test_kubernetes_versions_in_hieradata(self):
        config = self.operator.kubernetes._get_kubeadm_kubelet_version(self.host)

        kubeadm_version = config.get("platform::kubernetes::params::kubeadm_version")
        kubelet_version = config.get("platform::kubernetes::params::kubelet_version")

        self.assertEqual(kubeadm_version, kubernetes.KUBERNETES_DEFAULT_VERSION)
        self.assertEqual(kubelet_version, kubernetes.KUBERNETES_DEFAULT_VERSION)

    def test_kubernetes_versions_in_hieradata_upgrade_started(self):
        dbutils.create_test_kube_upgrade(
            from_version=kubernetes.KUBERNETES_DEFAULT_VERSION,
            to_version='v1.19.13',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
        )

        dbutils.update_kube_host_upgrade(
            target_version='v1.19.13',
            status=kubernetes.KUBE_HOST_UPGRADING_CONTROL_PLANE,
        )

        config = self.operator.kubernetes._get_kubeadm_kubelet_version(self.host)

        kubeadm_version = config.get("platform::kubernetes::params::kubeadm_version")
        kubelet_version = config.get("platform::kubernetes::params::kubelet_version")

        self.assertEqual(kubeadm_version, '1.19.13')
        self.assertEqual(kubelet_version, kubernetes.KUBERNETES_DEFAULT_VERSION)

    def test_kubernetes_versions_in_hieradata_upgrade_kubelet(self):
        dbutils.create_test_kube_upgrade(
            from_version=kubernetes.KUBERNETES_DEFAULT_VERSION,
            to_version='v1.19.13',
            state=kubernetes.KUBE_UPGRADING_KUBELETS,
        )

        dbutils.update_kube_host_upgrade(
            target_version='v1.19.13',
            status=kubernetes.KUBE_HOST_UPGRADING_KUBELET,
        )

        config = self.operator.kubernetes._get_kubeadm_kubelet_version(self.host)

        kubeadm_version = config.get("platform::kubernetes::params::kubeadm_version")
        kubelet_version = config.get("platform::kubernetes::params::kubelet_version")

        self.assertEqual(kubeadm_version, '1.19.13')
        self.assertEqual(kubelet_version, '1.19.13')
