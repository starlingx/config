#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import unittest
from unittest import mock

from cgtsclient import exc
from cgtsclient.v1.network_addrpool import NetworkAddrPoolManager
from cgtsclient.v1.partition import partitionManager
from cgtsclient.v1.pci_device import PciDeviceManager
from cgtsclient.v1.port import PortManager
from cgtsclient.v1.ptp import ptpManager
from cgtsclient.v1.ptp_instance import PtpInstanceManager
from cgtsclient.v1.ptp_interface import PtpInterfaceManager
from cgtsclient.v1.ptp_parameter import PtpParameterManager
from cgtsclient.v1.registry_image import RegistryImageManager
from cgtsclient.v1.remotelogging import RemoteLoggingManager
from cgtsclient.v1.route import RouteManager
from cgtsclient.v1.sdn_controller import SDNControllerManager
from cgtsclient.v1.service_parameter import ServiceParameterManager
from cgtsclient.v1.sm_service import SmServiceManager
from cgtsclient.v1.sm_service_nodes import SmNodesManager
from cgtsclient.v1.sm_servicegroup import SmServiceGroupManager
from cgtsclient.v1.storage_backend import StorageBackendManager
from cgtsclient.v1.storage_ceph import StorageCephManager
from cgtsclient.v1.storage_ceph_external import StorageCephExternalManager
from cgtsclient.v1.storage_ceph_rook import StorageCephRookManager
from cgtsclient.v1.storage_external import StorageExternalManager
from cgtsclient.v1.storage_file import StorageFileManager
from cgtsclient.v1.storage_lvm import StorageLvmManager
from cgtsclient.v1.storage_tier import StorageTierManager
from cgtsclient.v1.upgrade import UpgradeManager


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


class TestNetworkAddrpoolManager(unittest.TestCase):
    def test_list(self):
        mgr = NetworkAddrPoolManager(
            _FakeAPI({'network_addresspools': [ITEM]})
        )
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = NetworkAddrPoolManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = NetworkAddrPoolManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_assign_invalid(self):
        mgr = NetworkAddrPoolManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.assign(bad='x')


class TestPartitionManager(unittest.TestCase):
    def test_list(self):
        mgr = partitionManager(_FakeAPI({'partitions': [ITEM]}))
        self.assertEqual(len(mgr.list(FAKE_HOST)), 1)

    def test_list_with_disk(self):
        mgr = partitionManager(_FakeAPI({'partitions': [ITEM]}))
        self.assertEqual(len(mgr.list(FAKE_HOST, FAKE_ID)), 1)

    def test_get(self):
        mgr = partitionManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = partitionManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = partitionManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestPciDeviceManager(unittest.TestCase):
    def test_list(self):
        mgr = PciDeviceManager(_FakeAPI({'pci_devices': [ITEM]}))
        self.assertEqual(len(mgr.list(FAKE_HOST)), 1)

    def test_list_all(self):
        mgr = PciDeviceManager(_FakeAPI({'pci_devices': [ITEM]}))
        self.assertEqual(len(mgr.list_all()), 1)

    def test_get(self):
        mgr = PciDeviceManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = PciDeviceManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))


class TestPortManager(unittest.TestCase):
    def test_list(self):
        mgr = PortManager(_FakeAPI({'ports': [ITEM]}))
        self.assertEqual(len(mgr.list(FAKE_HOST)), 1)

    def test_get(self):
        mgr = PortManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = PortManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))


class TestPtpManager(unittest.TestCase):
    def test_list(self):
        mgr = ptpManager(_FakeAPI({'ptps': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = ptpManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = ptpManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = ptpManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestPtpInstanceManager(unittest.TestCase):
    def test_list(self):
        mgr = PtpInstanceManager(_FakeAPI({'ptp_instances': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_list_by_host(self):
        mgr = PtpInstanceManager(_FakeAPI({'ptp_instances': [ITEM]}))
        self.assertEqual(len(mgr.list_by_host(FAKE_HOST)), 1)

    def test_get(self):
        mgr = PtpInstanceManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = PtpInstanceManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = PtpInstanceManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestPtpInterfaceManager(unittest.TestCase):
    def test_list(self):
        mgr = PtpInterfaceManager(_FakeAPI({'ptp_interfaces': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_list_by_host(self):
        mgr = PtpInterfaceManager(_FakeAPI({'ptp_interfaces': [ITEM]}))
        self.assertEqual(len(mgr.list_by_host(FAKE_HOST)), 1)

    def test_list_by_interface(self):
        mgr = PtpInterfaceManager(_FakeAPI({'ptp_interfaces': [ITEM]}))
        self.assertEqual(len(mgr.list_by_interface(FAKE_ID)), 1)

    def test_get(self):
        mgr = PtpInterfaceManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = PtpInterfaceManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = PtpInterfaceManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestPtpParameterManager(unittest.TestCase):
    def test_list(self):
        mgr = PtpParameterManager(_FakeAPI({'ptp_parameters': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_list_by_ptp_instance(self):
        mgr = PtpParameterManager(_FakeAPI({'ptp_parameters': [ITEM]}))
        self.assertEqual(len(mgr.list_by_ptp_instance(FAKE_ID)), 1)

    def test_list_by_ptp_interface(self):
        mgr = PtpParameterManager(_FakeAPI({'ptp_parameters': [ITEM]}))
        self.assertEqual(len(mgr.list_by_ptp_interface(FAKE_ID)), 1)

    def test_get(self):
        mgr = PtpParameterManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = PtpParameterManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = PtpParameterManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestRegistryImageManager(unittest.TestCase):
    def test_list(self):
        mgr = (
            RegistryImageManager(_FakeAPI({'registry_images': [ITEM]}))
        )
        self.assertEqual(len(mgr.list(False)), 1)

    def test_list_filtered(self):
        mgr = (
            RegistryImageManager(_FakeAPI({'registry_images': [ITEM]}))
        )
        self.assertEqual(len(mgr.list(True)), 1)

    def test_tags(self):
        mgr = (
            RegistryImageManager(_FakeAPI({'registry_images': [ITEM]}))
        )
        self.assertEqual(len(mgr.tags('myimage')), 1)


class TestRemoteLoggingManager(unittest.TestCase):
    def test_list(self):
        mgr = RemoteLoggingManager(_FakeAPI({'remoteloggings': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = RemoteLoggingManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = RemoteLoggingManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = RemoteLoggingManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestRouteManager(unittest.TestCase):
    def test_list(self):
        mgr = RouteManager(_FakeAPI({'routes': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_list_by_interface(self):
        mgr = RouteManager(_FakeAPI({'routes': [ITEM]}))
        self.assertEqual(len(mgr.list_by_interface(FAKE_ID)), 1)

    def test_list_by_host(self):
        mgr = RouteManager(_FakeAPI({'routes': [ITEM]}))
        self.assertEqual(len(mgr.list_by_host(FAKE_HOST)), 1)

    def test_get(self):
        mgr = RouteManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = RouteManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = RouteManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestSDNControllerManager(unittest.TestCase):
    def test_list(self):
        mgr = (
            SDNControllerManager(_FakeAPI({'sdn_controllers': [ITEM]}))
        )
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = SDNControllerManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = SDNControllerManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = SDNControllerManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestServiceParameterManager(unittest.TestCase):
    def test_list(self):
        mgr = ServiceParameterManager(_FakeAPI({'parameters': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = ServiceParameterManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = ServiceParameterManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))


class TestSmServiceManager(unittest.TestCase):
    def test_list(self):
        mgr = SmServiceManager(_FakeAPI({'services': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = SmServiceManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = SmServiceManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = SmServiceManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')

    def test_service_create_invalid(self):
        mgr = SmServiceManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.service_create(bad='x')


class TestSmNodesManager(unittest.TestCase):
    def test_list(self):
        mgr = SmNodesManager(_FakeAPI({'nodes': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = SmNodesManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = SmNodesManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = SmNodesManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestSmServiceGroupManager(unittest.TestCase):
    def test_list(self):
        mgr = (
            SmServiceGroupManager(_FakeAPI({'sm_servicegroup': [ITEM]}))
        )
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = SmServiceGroupManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = SmServiceGroupManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = SmServiceGroupManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestUpgradeManager(unittest.TestCase):
    def test_list(self):
        mgr = UpgradeManager(_FakeAPI({'upgrades': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = UpgradeManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = UpgradeManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_delete_nobody(self):
        mgr = UpgradeManager(_FakeAPI({}))
        result = mgr.delete()
        self.assertIsNone(result)


class TestStorageBackendManager(unittest.TestCase):
    def test_list(self):
        mgr = StorageBackendManager(
            _FakeAPI({'storage_backends': [CAP_ITEM]})
        )
        self.assertEqual(len(mgr.list()), 1)

    def test_list_asdict(self):
        mgr = StorageBackendManager(
            _FakeAPI({'storage_backends': [CAP_ITEM]})
        )
        self.assertEqual(len(mgr.list(asdict=True)), 1)

    def test_get(self):
        mgr = StorageBackendManager(_FakeAPI(CAP_ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = StorageBackendManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = StorageBackendManager(_FakeAPI(CAP_ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestStorageCephManager(unittest.TestCase):
    def test_list(self):
        mgr = StorageCephManager(_FakeAPI({'storage_ceph': [CAP_ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = StorageCephManager(_FakeAPI(CAP_ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_no_id(self):
        mgr = StorageCephManager(_FakeAPI({'storage_ceph': [CAP_ITEM]}))
        self.assertIsNotNone(mgr.get())

    def test_get_none(self):
        mgr = StorageCephManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = StorageCephManager(_FakeAPI(CAP_ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestStorageCephExternalManager(unittest.TestCase):
    def test_list(self):
        mgr = StorageCephExternalManager(
            _FakeAPI({'storage_ceph_external': [CAP_ITEM]})
        )
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = StorageCephExternalManager(_FakeAPI(CAP_ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_no_id(self):
        mgr = StorageCephExternalManager(
            _FakeAPI({'storage_ceph_external': [CAP_ITEM]})
        )
        self.assertIsNotNone(mgr.get())

    def test_get_none(self):
        mgr = StorageCephExternalManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))


class TestStorageCephRookManager(unittest.TestCase):
    def test_list(self):
        mgr = StorageCephRookManager(
            _FakeAPI({'storage_ceph_rook': [CAP_ITEM]})
        )
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = StorageCephRookManager(_FakeAPI(CAP_ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_no_id(self):
        mgr = StorageCephRookManager(
            _FakeAPI({'storage_ceph_rook': [CAP_ITEM]})
        )
        self.assertIsNotNone(mgr.get())

    def test_get_none(self):
        mgr = StorageCephRookManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = StorageCephRookManager(_FakeAPI(CAP_ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestStorageExternalManager(unittest.TestCase):
    def test_list(self):
        mgr = StorageExternalManager(
            _FakeAPI({'storage_external': [CAP_ITEM]})
        )
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = StorageExternalManager(_FakeAPI(CAP_ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_no_id(self):
        mgr = StorageExternalManager(
            _FakeAPI({'storage_external': [CAP_ITEM]})
        )
        self.assertIsNotNone(mgr.get())

    def test_get_none(self):
        mgr = StorageExternalManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = StorageExternalManager(_FakeAPI(CAP_ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestStorageFileManager(unittest.TestCase):
    def test_list(self):
        mgr = StorageFileManager(_FakeAPI({'storage_file': [CAP_ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = StorageFileManager(_FakeAPI(CAP_ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_no_id(self):
        mgr = StorageFileManager(_FakeAPI({'storage_file': [CAP_ITEM]}))
        self.assertIsNotNone(mgr.get())

    def test_get_none(self):
        mgr = StorageFileManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = StorageFileManager(_FakeAPI(CAP_ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestStorageLvmManager(unittest.TestCase):
    def test_list(self):
        mgr = StorageLvmManager(_FakeAPI({'storage_lvm': [CAP_ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = StorageLvmManager(_FakeAPI(CAP_ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_no_id(self):
        mgr = StorageLvmManager(_FakeAPI({'storage_lvm': [CAP_ITEM]}))
        self.assertIsNotNone(mgr.get())

    def test_get_none(self):
        mgr = StorageLvmManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = StorageLvmManager(_FakeAPI(CAP_ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestStorageTierManager(unittest.TestCase):
    def test_list(self):
        mgr = StorageTierManager(_FakeAPI({'storage_tiers': [ITEM]}))
        self.assertEqual(len(mgr.list(FAKE_ID)), 1)

    def test_get(self):
        mgr = StorageTierManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = StorageTierManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = StorageTierManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')
