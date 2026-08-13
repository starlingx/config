#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import unittest
from unittest import mock

from cgtsclient import exc
from cgtsclient.v1.imemory import imemoryManager
from cgtsclient.v1.inode import inodeManager
from cgtsclient.v1.interface_datanetwork import InterfaceDataNetworkManager
from cgtsclient.v1.interface_network import InterfaceNetworkManager
from cgtsclient.v1.intp import intpManager
from cgtsclient.v1.ipv import ipvManager
from cgtsclient.v1.isensor import isensorManager
from cgtsclient.v1.isensorgroup import isensorgroupManager
from cgtsclient.v1.iservice import iServiceManager
from cgtsclient.v1.iservicegroup import iServiceGroupManager
from cgtsclient.v1.istor import istorManager
from cgtsclient.v1.isystem import isystemManager
from cgtsclient.v1.iuser import iuserManager
from cgtsclient.v1.kube_app import KubeAppManager
from cgtsclient.v1.kube_cluster import KubeClusterManager
from cgtsclient.v1.kube_cmd_version import KubeCmdVersionManager
from cgtsclient.v1.kube_host_upgrade import KubeHostUpgradeManager
from cgtsclient.v1.kube_rootca_update import KubeRootCAUpdateManager
from cgtsclient.v1.kube_upgrade import KubeUpgradeManager
from cgtsclient.v1.kube_version import KubeVersionManager
from cgtsclient.v1.label import KubernetesLabelManager
from cgtsclient.v1.lldp_agent import LldpAgentManager
from cgtsclient.v1.lldp_neighbour import LldpNeighbourManager
from cgtsclient.v1.network import NetworkManager


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


class TestImemoryManager(unittest.TestCase):
    def test_list(self):
        mgr = imemoryManager(_FakeAPI({'imemorys': [ITEM]}))
        self.assertEqual(len(mgr.list(FAKE_HOST)), 1)

    def test_get(self):
        mgr = imemoryManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = imemoryManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = imemoryManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestInodeManager(unittest.TestCase):
    def test_list(self):
        mgr = inodeManager(_FakeAPI({'inodes': [ITEM]}))
        self.assertEqual(len(mgr.list(FAKE_HOST)), 1)

    def test_get(self):
        mgr = inodeManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = inodeManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = inodeManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestInterfaceDataNetworkManager(unittest.TestCase):
    def test_list(self):
        mgr = InterfaceDataNetworkManager(
            _FakeAPI({'interface_datanetworks': [ITEM]})
        )
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = InterfaceDataNetworkManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = InterfaceDataNetworkManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_assign_invalid(self):
        mgr = InterfaceDataNetworkManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.assign(bad='x')

    def test_list_by_host(self):
        mgr = InterfaceDataNetworkManager(
            _FakeAPI({'interface_datanetworks': [ITEM]})
        )
        self.assertEqual(len(mgr.list_by_host(FAKE_HOST)), 1)

    def test_list_by_interface(self):
        mgr = InterfaceDataNetworkManager(
            _FakeAPI({'interface_datanetworks': [ITEM]})
        )
        self.assertEqual(len(mgr.list_by_interface(FAKE_ID)), 1)


class TestInterfaceNetworkManager(unittest.TestCase):
    def test_list(self):
        mgr = InterfaceNetworkManager(
            _FakeAPI({'interface_networks': [ITEM]})
        )
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = InterfaceNetworkManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = InterfaceNetworkManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_assign_invalid(self):
        mgr = InterfaceNetworkManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.assign(bad='x')

    def test_list_by_host(self):
        mgr = InterfaceNetworkManager(
            _FakeAPI({'interface_networks': [ITEM]})
        )
        self.assertEqual(len(mgr.list_by_host(FAKE_HOST)), 1)

    def test_list_by_interface(self):
        mgr = InterfaceNetworkManager(
            _FakeAPI({'interface_networks': [ITEM]})
        )
        self.assertEqual(len(mgr.list_by_interface(FAKE_ID)), 1)


class TestIntpManager(unittest.TestCase):
    def test_list(self):
        mgr = intpManager(_FakeAPI({'intps': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = intpManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = intpManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = intpManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestIpvManager(unittest.TestCase):
    def test_list(self):
        mgr = ipvManager(_FakeAPI({'ipvs': [ITEM]}))
        self.assertEqual(len(mgr.list(FAKE_HOST)), 1)

    def test_get(self):
        mgr = ipvManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = ipvManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = ipvManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestIsensorManager(unittest.TestCase):
    def test_list(self):
        mgr = isensorManager(_FakeAPI({'isensors': [ITEM]}))
        self.assertEqual(len(mgr.list(FAKE_HOST)), 1)

    def test_get(self):
        mgr = isensorManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = isensorManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = isensorManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')

    def test_list_by_sensorgroup(self):
        mgr = isensorManager(_FakeAPI({'isensors': [ITEM]}))
        self.assertEqual(len(mgr.list_by_sensorgroup(FAKE_ID)), 1)


class TestIsensorgroupManager(unittest.TestCase):
    def test_list(self):
        mgr = isensorgroupManager(_FakeAPI({'isensorgroups': [ITEM]}))
        self.assertEqual(len(mgr.list(FAKE_HOST)), 1)

    def test_get(self):
        mgr = isensorgroupManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = isensorgroupManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = isensorgroupManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestIserviceManager(unittest.TestCase):
    def test_list(self):
        mgr = iServiceManager(_FakeAPI({'iservice': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = iServiceManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = iServiceManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = iServiceManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestIservicegroupManager(unittest.TestCase):
    def test_list(self):
        mgr = iServiceGroupManager(_FakeAPI({'iservicegroup': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = iServiceGroupManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = iServiceGroupManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = iServiceGroupManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestIstorManager(unittest.TestCase):
    def test_list(self):
        mgr = istorManager(_FakeAPI({'istors': [ITEM]}))
        self.assertEqual(len(mgr.list(FAKE_HOST)), 1)

    def test_get(self):
        mgr = istorManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = istorManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = istorManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestIsystemManager(unittest.TestCase):
    def test_list(self):
        mgr = isystemManager(_FakeAPI({'isystems': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = isystemManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = isystemManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = isystemManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')

    def test_list_ihosts(self):
        mgr = isystemManager(_FakeAPI({'ihosts': [ITEM]}))
        self.assertEqual(len(mgr.list_ihosts(FAKE_ID)), 1)


class TestIuserManager(unittest.TestCase):
    def test_list(self):
        mgr = iuserManager(_FakeAPI({'iusers': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = iuserManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = iuserManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = iuserManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')


class TestKubeAppManager(unittest.TestCase):
    def test_get_all_apps(self):
        mgr = KubeAppManager(_FakeAPI({'apps': [ITEM]}))
        self.assertEqual(len(mgr.get_all_apps()), 1)


class TestKubeClusterManager(unittest.TestCase):
    def test_list(self):
        mgr = KubeClusterManager(_FakeAPI({'kube_clusters': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = KubeClusterManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get('kubernetes'))

    def test_get_none(self):
        mgr = KubeClusterManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get('kubernetes'))


class TestKubeCmdVersionManager(unittest.TestCase):
    def test_get(self):
        mgr = KubeCmdVersionManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get())

    def test_get_none(self):
        mgr = KubeCmdVersionManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get())


class TestKubeHostUpgradeManager(unittest.TestCase):
    def test_list(self):
        mgr = KubeHostUpgradeManager(
            _FakeAPI({'kube_host_upgrades': [ITEM]})
        )
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = KubeHostUpgradeManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = KubeHostUpgradeManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))


class TestKubeRootCAUpdateManager(unittest.TestCase):
    def test_get(self):
        mgr = KubeRootCAUpdateManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get())

    def test_get_uuid(self):
        mgr = KubeRootCAUpdateManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = KubeRootCAUpdateManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get())

    def test_get_list(self):
        mgr = KubeRootCAUpdateManager(
            _FakeAPI({'kube_rootca_updates': [ITEM]})
        )
        self.assertEqual(len(mgr.get_list()), 1)

    def test_get_cert_id_not_found(self):
        mgr = KubeRootCAUpdateManager(_FakeAPI(EMPTY))
        result = mgr.get_cert_id()
        self.assertIn('error', result)

    def test_host_update_list(self):
        mgr = KubeRootCAUpdateManager(
            _FakeAPI({'kube_host_updates': [ITEM]})
        )
        self.assertEqual(len(mgr.host_update_list()), 1)


class TestKubeUpgradeManager(unittest.TestCase):
    def test_list(self):
        mgr = KubeUpgradeManager(_FakeAPI({'kube_upgrades': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = KubeUpgradeManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = KubeUpgradeManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))


class TestKubeVersionManager(unittest.TestCase):
    def test_list(self):
        mgr = KubeVersionManager(_FakeAPI({'kube_versions': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = KubeVersionManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get('v1.25.0'))

    def test_get_none(self):
        mgr = KubeVersionManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get('v1.25.0'))


class TestKubernetesLabelManager(unittest.TestCase):
    def test_list(self):
        mgr = KubernetesLabelManager(_FakeAPI({'labels': [ITEM]}))
        self.assertEqual(len(mgr.list(FAKE_HOST)), 1)

    def test_get(self):
        mgr = KubernetesLabelManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = KubernetesLabelManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_assign_none(self):
        mgr = KubernetesLabelManager(_FakeAPI(None))
        result = mgr.assign(FAKE_HOST, {'key': 'val'})
        self.assertIsNone(result)


class TestLldpAgentManager(unittest.TestCase):
    def test_list(self):
        mgr = LldpAgentManager(_FakeAPI({'lldp_agents': [ITEM]}))
        self.assertEqual(len(mgr.list(FAKE_HOST)), 1)

    def test_get(self):
        mgr = LldpAgentManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = LldpAgentManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_get_by_port(self):
        mgr = LldpAgentManager(_FakeAPI({'lldp_agents': [ITEM]}))
        self.assertEqual(len(mgr.get_by_port(FAKE_ID)), 1)


class TestLldpNeighbourManager(unittest.TestCase):
    def test_list(self):
        mgr = (
            LldpNeighbourManager(_FakeAPI({'lldp_neighbours': [ITEM]}))
        )
        self.assertEqual(len(mgr.list(FAKE_HOST)), 1)

    def test_get(self):
        mgr = LldpNeighbourManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = LldpNeighbourManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_list_by_port(self):
        mgr = (
            LldpNeighbourManager(_FakeAPI({'lldp_neighbours': [ITEM]}))
        )
        self.assertEqual(len(mgr.list_by_port(FAKE_ID)), 1)


class TestNetworkManager(unittest.TestCase):
    def test_list(self):
        mgr = NetworkManager(_FakeAPI({'networks': [ITEM]}))
        self.assertEqual(len(mgr.list()), 1)

    def test_get(self):
        mgr = NetworkManager(_FakeAPI(ITEM))
        self.assertIsNotNone(mgr.get(FAKE_ID))

    def test_get_none(self):
        mgr = NetworkManager(_FakeAPI(EMPTY))
        self.assertIsNone(mgr.get(FAKE_ID))

    def test_create_invalid(self):
        mgr = NetworkManager(_FakeAPI(ITEM))
        with self.assertRaises(exc.InvalidAttribute):
            mgr.create(bad='x')
