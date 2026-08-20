#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for v1 resource managers - CRUD operations."""
import copy
import unittest
from unittest import mock

from cgtsclient.common import base
from cgtsclient import exc
from cgtsclient.v1 import address
from cgtsclient.v1 import address_pool
from cgtsclient.v1 import app
from cgtsclient.v1 import certificate
from cgtsclient.v1 import controller_fs
from cgtsclient.v1 import datanetwork
from cgtsclient.v1 import helm
from cgtsclient.v1 import host_fs
from cgtsclient.v1 import ihost
from cgtsclient.v1 import isystem
from cgtsclient.v1 import kube_cluster
from cgtsclient.v1 import kube_upgrade
from cgtsclient.v1 import kube_version
from cgtsclient.v1 import label
from cgtsclient.v1 import network
from cgtsclient.v1 import partition
from cgtsclient.v1 import ptp_instance
from cgtsclient.v1 import ptp_interface
from cgtsclient.v1 import ptp_parameter
from cgtsclient.v1 import route
from cgtsclient.v1 import service_parameter
from cgtsclient.v1 import storage_backend
from cgtsclient.v1 import upgrade


class _FakeAPI(object):
    """Fake API client for testing managers."""

    def __init__(self, json_body=None):
        self._json_body = json_body or {}

    def json_request(self, method, url, **kwargs):
        resp = mock.MagicMock(status_code=200)
        return resp, self._json_body

    def raw_request(self, method, url, **kwargs):
        return mock.MagicMock(status_code=200)

    def upload_request_with_data(self, method, url, **kwargs):
        return self._json_body

    def upload_request_with_multipart(self, method, url, **kwargs):
        return self._json_body


class TestBaseManager(unittest.TestCase):
    """Test base.Manager CRUD methods."""

    def test_create(self):
        api = _FakeAPI({'uuid': '123', 'name': 'test'})
        mgr = base.Manager(api)
        mgr.resource_class = base.Resource
        result = mgr._create('/v1/test', {'name': 'test'})
        self.assertIsInstance(result, base.Resource)
        self.assertEqual(result.uuid, '123')

    def test_create_empty_body(self):
        api = _FakeAPI({})
        mgr = base.Manager(api)
        mgr.resource_class = base.Resource
        result = mgr._create('/v1/test', {'name': 'test'})
        self.assertIsNone(result)

    def test_list_with_key(self):
        api = _FakeAPI({'items': [{'id': '1'}, {'id': '2'}]})
        mgr = base.Manager(api)
        mgr.resource_class = base.Resource
        result = mgr._list('/v1/test', 'items')
        self.assertEqual(len(result), 2)

    def test_list_missing_key(self):
        api = _FakeAPI({'other': []})
        mgr = base.Manager(api)
        mgr.resource_class = base.Resource
        result = mgr._list('/v1/test', 'items')
        self.assertEqual(result, [])

    def test_list_single_item(self):
        api = _FakeAPI({'id': '1', 'name': 'x'})
        mgr = base.Manager(api)
        mgr.resource_class = base.Resource
        result = mgr._list('/v1/test')
        self.assertEqual(len(result), 1)

    def test_update(self):
        api = _FakeAPI({'uuid': '1', 'name': 'updated'})
        mgr = base.Manager(api)
        mgr.resource_class = base.Resource
        result = mgr._update('/v1/test/1', [{'op': 'replace'}])
        self.assertEqual(result.name, 'updated')

    def test_update_empty(self):
        api = _FakeAPI({})
        mgr = base.Manager(api)
        mgr.resource_class = base.Resource
        result = mgr._update('/v1/test/1', [])
        self.assertIsNone(result)

    def test_upload(self):
        api = _FakeAPI({'result': 'ok'})
        mgr = base.Manager(api)
        result = mgr._upload('/v1/test', b'data')
        self.assertEqual(result['result'], 'ok')

    def test_json_get(self):
        api = _FakeAPI({'key': 'val'})
        mgr = base.Manager(api)
        result = mgr._json_get('/v1/test')
        self.assertEqual(result['key'], 'val')


class TestBaseResource(unittest.TestCase):
    """Test base.Resource."""

    def test_resource_attrs(self):
        mgr = mock.MagicMock()
        r = base.Resource(mgr, {'id': '1', 'name': 'test'}, loaded=True)
        self.assertEqual(r.id, '1')
        self.assertEqual(r.name, 'test')

    def test_resource_repr(self):
        mgr = mock.MagicMock()
        r = base.Resource(mgr, {'id': '1', 'name': 'test'}, loaded=True)
        self.assertIn('Resource', repr(r))

    def test_resource_to_dict(self):
        mgr = mock.MagicMock()
        r = base.Resource(mgr, {'id': '1'}, loaded=True)
        d = r.to_dict()
        self.assertEqual(d, {'id': '1'})

    def test_resource_eq(self):
        mgr = mock.MagicMock()
        r1 = base.Resource(mgr, {'id': '1'}, loaded=True)
        r2 = base.Resource(mgr, {'id': '1'}, loaded=True)
        self.assertEqual(r1, r2)

    def test_resource_neq_different_class(self):
        mgr = mock.MagicMock()
        r = base.Resource(mgr, {'id': '1'}, loaded=True)
        self.assertNotEqual(r, 'string')

    def test_resource_loaded(self):
        mgr = mock.MagicMock()
        r = base.Resource(mgr, {'id': '1'}, loaded=False)
        self.assertFalse(r.is_loaded())
        r.set_loaded(True)
        self.assertTrue(r.is_loaded())

    def test_resource_getattr_loaded(self):
        mgr = mock.MagicMock()
        r = base.Resource(mgr, {'id': '1'}, loaded=True)
        with self.assertRaises(AttributeError):
            _ = r.nonexistent

    def test_resource_copy(self):
        mgr = mock.MagicMock()
        r = base.Resource(mgr, {'id': '1'}, loaded=True)
        r2 = copy.copy(r)
        self.assertEqual(r2.id, '1')

    def test_resource_deepcopy(self):
        mgr = mock.MagicMock()
        r = base.Resource(mgr, {'id': '1'}, loaded=True)
        r2 = copy.deepcopy(r)
        self.assertEqual(r2.id, '1')

    def test_getid_with_obj(self):
        mgr = mock.MagicMock()
        r = base.Resource(mgr, {'id': '1'}, loaded=True)
        self.assertEqual(base.getid(r), '1')

    def test_getid_with_string(self):
        self.assertEqual(base.getid('abc'), 'abc')


class TestV1Managers(unittest.TestCase):
    """Test v1 resource manager methods."""

    def _make_mgr(self, cls, body=None):
        api = _FakeAPI(body or {})
        return cls(api)

    def test_address_manager_list(self):
        api = _FakeAPI({'addresses': [{'uuid': '1'}]})
        mgr = address.AddressManager(api)
        result = mgr.list()
        self.assertEqual(len(result), 1)

    def test_address_manager_get(self):
        api = _FakeAPI({'uuid': 'a1', 'address': '10.0.0.1'})
        mgr = address.AddressManager(api)
        result = mgr.get('a1')
        self.assertEqual(result.uuid, 'a1')

    def test_address_manager_get_not_found(self):
        api = _FakeAPI({'addresses': []})
        api.json_request = (
            mock.MagicMock(return_value=(mock.MagicMock(), []))
        )
        mgr = address.AddressManager(api)
        result = mgr.get('missing')
        self.assertIsNone(result)

    def test_address_manager_create(self):
        api = _FakeAPI({'uuid': 'new', 'address': '10.0.0.2'})
        mgr = address.AddressManager(api)
        result = mgr.create(address='10.0.0.2', prefix=24)
        self.assertEqual(result.uuid, 'new')

    def test_address_manager_create_invalid_attr(self):
        api = _FakeAPI({})
        mgr = address.AddressManager(api)
        self.assertRaises(exc.InvalidAttribute, mgr.create, bad_key='x')

    def test_address_manager_list_by_host(self):
        api = _FakeAPI({'addresses': [{'uuid': '1'}]})
        mgr = address.AddressManager(api)
        result = mgr.list_by_host('host1')
        self.assertEqual(len(result), 1)

    def test_address_manager_list_by_interface(self):
        api = _FakeAPI({'addresses': []})
        mgr = address.AddressManager(api)
        result = mgr.list_by_interface('iface1')
        self.assertEqual(result, [])

    def test_app_manager_list(self):
        api = _FakeAPI({'apps': [{'name': 'a1'}]})
        mgr = app.AppManager(api)
        result = mgr.list()
        self.assertEqual(len(result), 1)

    def test_app_manager_get(self):
        api = _FakeAPI({'name': 'a1', 'status': 'applied'})
        mgr = app.AppManager(api)
        result = mgr.get('a1')
        self.assertEqual(result.name, 'a1')

    def test_app_manager_upload(self):
        api = _FakeAPI({'name': 'a1'})
        mgr = app.AppManager(api)
        result = mgr.upload({'name': 'a1'})
        self.assertEqual(result.name, 'a1')

    def test_app_manager_apply(self):
        api = _FakeAPI({'name': 'a1'})
        mgr = app.AppManager(api)
        result = mgr.apply('a1', {})
        self.assertEqual(result.name, 'a1')

    def test_app_manager_remove(self):
        api = _FakeAPI({'name': 'a1'})
        mgr = app.AppManager(api)
        result = mgr.remove('a1', force=False)
        self.assertEqual(result.name, 'a1')

    def test_app_manager_abort(self):
        api = _FakeAPI({'name': 'a1'})
        mgr = app.AppManager(api)
        result = mgr.abort('a1')
        self.assertEqual(result.name, 'a1')

    def test_app_manager_update(self):
        api = _FakeAPI({'name': 'a1'})
        mgr = app.AppManager(api)
        result = mgr.update({'name': 'a1'})
        self.assertEqual(result.name, 'a1')

    def test_find_app_success(self):
        cc = mock.MagicMock()
        cc.app.get.return_value = mock.MagicMock(name='myapp')
        result = app._find_app(cc, 'myapp')
        self.assertIsNotNone(result)

    def test_find_app_not_found(self):
        cc = mock.MagicMock()
        cc.app.get.side_effect = exc.HTTPNotFound()
        self.assertRaises(exc.CommandError,
                          app._find_app,
                          cc,
                          'missing')

    def test_ihost_manager_list(self):
        api = _FakeAPI({'ihosts': [{'uuid': 'h1'}]})
        mgr = ihost.ihostManager(api)
        result = mgr.list()
        self.assertEqual(len(result), 1)

    def test_ihost_manager_get(self):
        api = _FakeAPI({'uuid': 'h1', 'hostname': 'ctrl-0'})
        mgr = ihost.ihostManager(api)
        result = mgr.get('h1')
        self.assertEqual(result.hostname, 'ctrl-0')

    def test_ihost_manager_create(self):
        api = _FakeAPI({'uuid': 'h1', 'hostname': 'ctrl-0'})
        mgr = ihost.ihostManager(api)
        result = mgr.create(hostname='ctrl-0', personality='controller',
                            mgmt_mac='00:00:00:00:00:01')
        self.assertEqual(result.hostname, 'ctrl-0')

    def test_ihost_manager_create_invalid(self):
        api = _FakeAPI({})
        mgr = ihost.ihostManager(api)
        self.assertRaises(exc.InvalidAttribute, mgr.create, bad_key='x')

    def test_ihost_manager_update(self):
        api = _FakeAPI({'uuid': 'h1', 'hostname': 'new'})
        mgr = ihost.ihostManager(api)
        result = mgr.update('h1', [{'op': 'replace'}])
        self.assertEqual(result.hostname, 'new')

    def test_ihost_manager_bulk_export(self):
        api = _FakeAPI({'hosts': []})
        mgr = ihost.ihostManager(api)
        result = mgr.bulk_export()
        self.assertIsNotNone(result)

    def test_ihost_manager_list_port(self):
        api = _FakeAPI({'ports': [{'uuid': 'p1'}]})
        mgr = ihost.ihostManager(api)
        result = mgr.list_port('h1')
        self.assertEqual(len(result), 1)

    def test_ihost_manager_list_ethernet_port(self):
        api = _FakeAPI({'ethernet_ports': [{'uuid': 'e1'}]})
        mgr = ihost.ihostManager(api)
        result = mgr.list_ethernet_port('h1')
        self.assertEqual(len(result), 1)

    def test_ihost_manager_list_iinterface(self):
        api = _FakeAPI({'iinterfaces': [{'uuid': 'i1'}]})
        mgr = ihost.ihostManager(api)
        result = mgr.list_iinterface('h1')
        self.assertEqual(len(result), 1)

    def test_ihost_manager_list_personality(self):
        api = _FakeAPI({'ihosts': [{'uuid': 'h1'}]})
        mgr = ihost.ihostManager(api)
        result = mgr.list_personality('controller')
        self.assertEqual(len(result), 1)

    def test_ihost_kube_upgrade_control_plane(self):
        api = _FakeAPI({'uuid': 'h1'})
        mgr = ihost.ihostManager(api)
        result = mgr.kube_upgrade_control_plane('h1', False)
        self.assertIsNotNone(result)

    def test_ihost_kube_upgrade_kubelet(self):
        api = _FakeAPI({'uuid': 'h1'})
        mgr = ihost.ihostManager(api)
        result = mgr.kube_upgrade_kubelet('h1', False)
        self.assertIsNotNone(result)

    def test_ihost_kube_update_rootca(self):
        api = _FakeAPI({'uuid': 'h1'})
        mgr = ihost.ihostManager(api)
        result = mgr.kube_update_rootca('h1', 'trust-both-cas')
        self.assertIsNotNone(result)

    def test_ihost_device_image_update(self):
        api = _FakeAPI({'uuid': 'h1'})
        mgr = ihost.ihostManager(api)
        result = mgr.device_image_update('h1')
        self.assertIsNotNone(result)

    def test_ihost_device_image_update_abort(self):
        api = _FakeAPI({'uuid': 'h1'})
        mgr = ihost.ihostManager(api)
        result = mgr.device_image_update_abort('h1')
        self.assertIsNotNone(result)

    def test_ihost_host_kernel_modify(self):
        api = _FakeAPI({'kernel': 'std'})
        mgr = ihost.ihostManager(api)
        result = mgr.host_kernel_modify('h1', {'kernel': 'std'})
        self.assertIsNotNone(result)

    def test_ihost_host_kernel_show(self):
        api = _FakeAPI({'kernel': 'std'})
        mgr = ihost.ihostManager(api)
        result = mgr.host_kernel_show('h1')
        self.assertIsNotNone(result)

    def test_ihost_host_cpus_modify(self):
        api = _FakeAPI({'icpus': [{'uuid': 'c1'}]})
        mgr = ihost.ihostManager(api)
        result = mgr.host_cpus_modify('h1',
                                      {'function': 'platform',
                                          'sockets': [{'0': 1}]}
                                      )
        self.assertEqual(len(result), 1)

    def test_ihost_host_cpus_modify_empty(self):
        api = _FakeAPI({'other': 'data'})
        mgr = ihost.ihostManager(api)
        result = mgr.host_cpus_modify('h1', {})
        self.assertEqual(result, [])

    def test_ihost_create_many(self):
        api = _FakeAPI({'result': 'ok'})
        mgr = ihost.ihostManager(api)
        result = mgr.create_many(b'csv_data')
        self.assertEqual(result['result'], 'ok')

    def test_ihost_vim_host_audit(self):
        api = _FakeAPI({'vim': 'ok'})
        mgr = ihost.ihostManager(api)
        result = mgr.vim_host_audit('h1')
        self.assertIsNotNone(result)

    def test_find_ihost_by_uuid(self):
        cc = mock.MagicMock()
        cc.ihost.get.return_value = mock.MagicMock(hostname='ctrl-0')
        result = ihost._find_ihost(cc,
                                   'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'
                                   )
        self.assertEqual(result.hostname, 'ctrl-0')

    def test_find_ihost_by_name(self):
        cc = mock.MagicMock()
        h = mock.MagicMock()
        h.hostname = 'ctrl-0'
        cc.ihost.list.return_value = [h]
        result = ihost._find_ihost(cc, 'ctrl-0')
        self.assertEqual(result.hostname, 'ctrl-0')

    def test_find_ihost_not_found(self):
        cc = mock.MagicMock()
        cc.ihost.list.return_value = []
        self.assertRaises(exc.CommandError,
                          ihost._find_ihost,
                          cc,
                          'missing')

    def test_find_ihost_by_id_not_found(self):
        cc = mock.MagicMock()
        cc.ihost.get.side_effect = exc.HTTPNotFound()
        self.assertRaises(exc.CommandError,
                          ihost._find_ihost,
                          cc,
                          '123')


class TestMoreV1Managers(unittest.TestCase):
    """Test additional v1 resource managers."""

    def test_address_pool_manager(self):
        api = _FakeAPI({'addrpools': [{'uuid': 'p1'}]})
        mgr = address_pool.AddressPoolManager(api)
        self.assertEqual(len(mgr.list()), 1)

    def test_network_manager(self):
        api = _FakeAPI({'networks': [{'uuid': 'n1'}]})
        mgr = network.NetworkManager(api)
        self.assertEqual(len(mgr.list()), 1)

    def test_route_manager(self):
        api = _FakeAPI({'routes': [{'uuid': 'r1'}]})
        mgr = route.RouteManager(api)
        self.assertEqual(len(mgr.list_by_host('h1')), 1)

    def test_label_manager(self):
        api = _FakeAPI({'labels': [{'uuid': 'l1'}]})
        mgr = label.KubernetesLabelManager(api)
        self.assertEqual(len(mgr.list('h1')), 1)

    def test_upgrade_manager(self):
        api = _FakeAPI({'uuid': 'u1'})
        mgr = upgrade.UpgradeManager(api)
        result = mgr.get('u1')
        self.assertIsNotNone(result)

    def test_kube_upgrade_manager(self):
        api = _FakeAPI({'uuid': 'ku1'})
        mgr = kube_upgrade.KubeUpgradeManager(api)
        result = mgr.get('ku1')
        self.assertIsNotNone(result)

    def test_kube_version_manager(self):
        api = _FakeAPI({'kube_versions': [{'version': 'v1.24.4'}]})
        mgr = kube_version.KubeVersionManager(api)
        self.assertEqual(len(mgr.list()), 1)

    def test_kube_cluster_manager(self):
        api = _FakeAPI({'kube_clusters': [{'cluster_name': 'k8s'}]})
        mgr = kube_cluster.KubeClusterManager(api)
        self.assertEqual(len(mgr.list()), 1)

    def test_controller_fs_manager(self):
        api = _FakeAPI({'controller_fs': [{'uuid': 'fs1'}]})
        mgr = controller_fs.ControllerFsManager(api)
        self.assertEqual(len(mgr.list()), 1)

    def test_isystem_manager(self):
        api = _FakeAPI({'isystems': [{'uuid': 's1'}]})
        mgr = isystem.isystemManager(api)
        self.assertEqual(len(mgr.list()), 1)

    def test_service_parameter_manager(self):
        api = _FakeAPI({'parameters': [{'uuid': 'sp1'}]})
        mgr = service_parameter.ServiceParameterManager(api)
        self.assertEqual(len(mgr.list()), 1)

    def test_certificate_manager(self):
        api = _FakeAPI({'certificates': [{'uuid': 'c1'}]})
        mgr = certificate.CertificateManager(api)
        self.assertEqual(len(mgr.list()), 1)

    def test_storage_backend_manager(self):
        api = _FakeAPI(
            {'storage_backends': [{'uuid': 'sb1', 'capabilities': {}}]}
        )
        mgr = storage_backend.StorageBackendManager(api)
        self.assertEqual(len(mgr.list()), 1)

    def test_helm_manager(self):
        api = _FakeAPI({'charts': [{'name': 'c1'}]})
        mgr = helm.HelmManager(api)
        result = mgr.list_charts('myapp')
        self.assertIsNotNone(result)

    def test_ptp_instance_manager(self):
        api = _FakeAPI({'ptp_instances': [{'uuid': 'pt1'}]})
        mgr = ptp_instance.PtpInstanceManager(api)
        self.assertEqual(len(mgr.list()), 1)

    def test_ptp_interface_manager(self):
        api = _FakeAPI({'ptp_interfaces': [{'uuid': 'pi1'}]})
        mgr = ptp_interface.PtpInterfaceManager(api)
        self.assertEqual(len(mgr.list()), 1)

    def test_ptp_parameter_manager(self):
        api = _FakeAPI({'ptp_parameters': [{'uuid': 'pp1'}]})
        mgr = ptp_parameter.PtpParameterManager(api)
        self.assertEqual(len(mgr.list()), 1)

    def test_datanetwork_manager(self):
        api = _FakeAPI({'datanetworks': [{'uuid': 'dn1'}]})
        mgr = datanetwork.DataNetworkManager(api)
        self.assertEqual(len(mgr.list()), 1)

    def test_partition_manager(self):
        api = _FakeAPI({'partitions': [{'uuid': 'p1'}]})
        mgr = partition.partitionManager(api)
        self.assertEqual(len(mgr.list('h1')), 1)

    def test_host_fs_manager(self):
        api = _FakeAPI({'host_fs': [{'uuid': 'hf1'}]})
        mgr = host_fs.HostFsManager(api)
        self.assertEqual(len(mgr.list('h1')), 1)


if __name__ == '__main__':
    unittest.main()
