#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import unittest
from unittest import mock

from cgtsclient import exc
from cgtsclient.v1.address import AddressManager
from cgtsclient.v1.address_pool import AddressPoolManager
from cgtsclient.v1.app import AppManager
from cgtsclient.v1.ceph_mon import CephMonManager
from cgtsclient.v1.certificate import CertificateManager
from cgtsclient.v1.cluster import ClusterManager
from cgtsclient.v1.controller_fs import ControllerFsManager
from cgtsclient.v1.datanetwork import DataNetworkManager
from cgtsclient.v1.device_image import DeviceImageManager
from cgtsclient.v1.device_image_state import DeviceImageStateManager
from cgtsclient.v1.device_label import DeviceLabelManager
from cgtsclient.v1.drbdconfig import drbdconfigManager
from cgtsclient.v1.ethernetport import EthernetPortManager
from cgtsclient.v1.fernet import FernetManager
from cgtsclient.v1.health import HealthManager
from cgtsclient.v1.helm import HelmManager
from cgtsclient.v1.host_fs import HostFsManager
from cgtsclient.v1.icpu import icpuManager
from cgtsclient.v1.idisk import idiskManager
from cgtsclient.v1.idns import idnsManager
from cgtsclient.v1.iextoam import iextoamManager
from cgtsclient.v1.ihost import ihostManager
from cgtsclient.v1.iinterface import iinterfaceManager
from cgtsclient.v1.ilvg import ilvgManager


class _FakeAPI:
    def __init__(self, json_body=None):
        self._json_body = json_body or {}

    def json_request(self, method, url, **kwargs):
        return mock.MagicMock(status_code=200), self._json_body

    def raw_request(self, method, url, **kwargs):
        return mock.MagicMock(status_code=200)

    def upload_request_with_data(self, method, url, **kwargs):
        return self._json_body

    def upload_request_with_multipart(self, method, url, **kwargs):
        return self._json_body


FAKE_ID = 'fake-uuid-1234'
FAKE_HOST = 'fake-host-uuid'
ITEM = {'uuid': FAKE_ID, 'id': 1}
CAP_ITEM = {'uuid': FAKE_ID, 'id': 1, 'capabilities': {}}
PATCH = [{'path': '/name', 'value': 'x', 'op': 'replace'}]
EMPTY = []  # triggers IndexError in get() via _list


class TestAddressManager(unittest.TestCase):
    def test_list(self):
        mgr = AddressManager(_FakeAPI({'addresses': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = AddressManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = AddressManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create(self):
        mgr = AddressManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.create(address='1.2.3.4'))

    def test_create_invalid(self):
        mgr = AddressManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad_attr='x')

    def test_list_by_host(self):
        mgr = AddressManager(_FakeAPI({'addresses': [ITEM]}))
        self.assertEqual(len(mgr.list_by_host(FAKE_HOST)), 1)

    def test_list_by_interface(self):
        mgr = AddressManager(_FakeAPI({'addresses': [ITEM]}))
        self.assertEqual(len(mgr.list_by_interface(FAKE_ID)), 1)


class TestAddressPoolManager(unittest.TestCase):
    def test_list(self):
        mgr = AddressPoolManager(_FakeAPI({'addrpools': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = AddressPoolManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = AddressPoolManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create(self):
        mgr = AddressPoolManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.create(name='pool1'))

    def test_create_invalid(self):
        mgr = AddressPoolManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestAppManager(unittest.TestCase):
    def test_list(self):
        mgr = AppManager(_FakeAPI({'apps': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = AppManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get('myapp'))

    def test_get_none(self):
        mgr = AppManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get('myapp'))


class TestCephMonManager(unittest.TestCase):
    def test_list(self):
        mgr = CephMonManager(_FakeAPI({'ceph_mon': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_list_host(self):
        mgr = CephMonManager(_FakeAPI({'ceph_mon': [ITEM]}))
        self.assertEqual(len(mgr.list(FAKE_HOST)), 1)

    def test_get(self):
        mgr = CephMonManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = CephMonManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = CephMonManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestCertificateManager(unittest.TestCase):
    def test_list(self):
        mgr = CertificateManager(_FakeAPI({'certificates': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = CertificateManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = CertificateManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))


class TestClusterManager(unittest.TestCase):
    def test_list(self):
        mgr = ClusterManager(_FakeAPI({'clusters': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = ClusterManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = ClusterManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = ClusterManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestControllerFsManager(unittest.TestCase):
    def test_list(self):
        mgr = ControllerFsManager(_FakeAPI({'controller_fs': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = ControllerFsManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = ControllerFsManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = ControllerFsManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestDataNetworkManager(unittest.TestCase):
    def test_list(self):
        mgr = DataNetworkManager(_FakeAPI({'datanetworks': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = DataNetworkManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = DataNetworkManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = DataNetworkManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestDeviceImageManager(unittest.TestCase):
    def test_list(self):
        mgr = DeviceImageManager(_FakeAPI({'device_images': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = DeviceImageManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = DeviceImageManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))


class TestDeviceImageStateManager(unittest.TestCase):
    def test_list(self):
        mgr = DeviceImageStateManager(
            _FakeAPI({'device_image_state': [ITEM]})
        )
        self.assertEqual(len(mgr.list()), 1)


class TestDeviceLabelManager(unittest.TestCase):
    def test_list(self):
        mgr = DeviceLabelManager(_FakeAPI({'device_labels': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = DeviceLabelManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = DeviceLabelManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))


class TestDrbdconfigManager(unittest.TestCase):
    def test_list(self):
        mgr = drbdconfigManager(_FakeAPI({'drbdconfigs': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = drbdconfigManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = drbdconfigManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = drbdconfigManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestEthernetPortManager(unittest.TestCase):
    def test_list(self):
        mgr = EthernetPortManager(_FakeAPI({'ethernet_ports': [ITEM]}))
        self.assertEqual(len(mgr.list(FAKE_HOST)), 1)

    def test_get(self):
        mgr = EthernetPortManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = EthernetPortManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = EthernetPortManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestFernetManager(unittest.TestCase):
    def test_list(self):
        mgr = FernetManager(_FakeAPI({'keys': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = FernetManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = FernetManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))


class TestHealthManager(unittest.TestCase):
    def test_get(self):
        mgr = HealthManager(_FakeAPI({'health': 'ok'}))
        self.assertEqual(mgr.get(), {'health': 'ok'})


class TestHelmManager(unittest.TestCase):
    def test_list_charts(self):
        mgr = HelmManager(_FakeAPI({'charts': [ITEM]}))
        self.assertEqual(len(mgr.list_charts('myapp')), 1)

    def test_get_overrides(self):
        mgr = HelmManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get_overrides('app', 'chart', 'ns'))

    def test_get_overrides_none(self):
        mgr = HelmManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get_overrides('app', 'chart', 'ns'))


class TestHostFsManager(unittest.TestCase):
    def test_list(self):
        mgr = HostFsManager(_FakeAPI({'host_fs': [ITEM]}))
        self.assertEqual(len(mgr.list(FAKE_HOST)), 1)

    def test_get(self):
        mgr = HostFsManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = HostFsManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = HostFsManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestIcpuManager(unittest.TestCase):
    def test_list(self):
        mgr = icpuManager(_FakeAPI({'icpus': [ITEM]}))
        self.assertEqual(len(mgr.list(FAKE_HOST)), 1)

    def test_get(self):
        mgr = icpuManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = icpuManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = icpuManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestIdiskManager(unittest.TestCase):
    def test_list(self):
        mgr = idiskManager(_FakeAPI({'idisks': [ITEM]}))
        self.assertEqual(len(mgr.list(FAKE_HOST)), 1)

    def test_get(self):
        mgr = idiskManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = idiskManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = idiskManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestIdnsManager(unittest.TestCase):
    def test_list(self):
        mgr = idnsManager(_FakeAPI({'idnss': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = idnsManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = idnsManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = idnsManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestIextoamManager(unittest.TestCase):
    def test_list(self):
        mgr = iextoamManager(_FakeAPI({'iextoams': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = iextoamManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = iextoamManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = iextoamManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestIhostManager(unittest.TestCase):
    def test_list(self):
        mgr = ihostManager(_FakeAPI({'ihosts': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = ihostManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = ihostManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = ihostManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')

    def test_list_port(self):
        mgr = ihostManager(_FakeAPI({'ports': [ITEM]}))
        self.assertEqual(len(mgr.list_port(FAKE_HOST)), 1)

    def test_list_ethernet_port(self):
        mgr = ihostManager(_FakeAPI({'ethernet_ports': [ITEM]}))
        self.assertEqual(len(mgr.list_ethernet_port(FAKE_HOST)), 1)

    def test_list_iinterface(self):
        mgr = ihostManager(_FakeAPI({'iinterfaces': [ITEM]}))
        self.assertEqual(len(mgr.list_iinterface(FAKE_HOST)), 1)

    def test_list_personality(self):
        mgr = ihostManager(_FakeAPI({'ihosts': [ITEM]}))
        self.assertEqual(len(mgr.list_personality('controller')), 1)

    def test_host_cpus_modify_empty(self):
        mgr = ihostManager(_FakeAPI({}))
        result = mgr.host_cpus_modify(FAKE_ID, PATCH)
        self.assertEqual(result, [])


class TestIinterfaceManager(unittest.TestCase):
    def test_list(self):
        mgr = iinterfaceManager(_FakeAPI({'iinterfaces': [ITEM]}))
        self.assertEqual(len(mgr.list(FAKE_HOST)), 1)

    def test_get(self):
        mgr = iinterfaceManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = iinterfaceManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = iinterfaceManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')

    def test_list_ports(self):
        mgr = iinterfaceManager(_FakeAPI({'ports': [ITEM]}))
        self.assertEqual(len(mgr.list_ports(FAKE_ID)), 1)


class TestIlvgManager(unittest.TestCase):
    def test_list(self):
        mgr = ilvgManager(_FakeAPI({'ilvgs': [ITEM]}))
        self.assertEqual(len(mgr.list(FAKE_HOST)), 1)

    def test_get(self):
        mgr = ilvgManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = ilvgManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = ilvgManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')
