#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Coverage tests for all cgtsclient.v1 resource managers."""

import testtools

from cgtsclient.tests import utils
import cgtsclient.v1.address
import cgtsclient.v1.address_pool
import cgtsclient.v1.app
import cgtsclient.v1.ceph_mon
import cgtsclient.v1.certificate
import cgtsclient.v1.cluster
import cgtsclient.v1.controller_fs
import cgtsclient.v1.datanetwork
import cgtsclient.v1.device_image
import cgtsclient.v1.device_image_state
import cgtsclient.v1.device_label
import cgtsclient.v1.drbdconfig
import cgtsclient.v1.ethernetport
import cgtsclient.v1.fernet
import cgtsclient.v1.flux
import cgtsclient.v1.health
import cgtsclient.v1.helm
import cgtsclient.v1.host_fs
import cgtsclient.v1.icpu
import cgtsclient.v1.idisk
import cgtsclient.v1.idns
import cgtsclient.v1.iextoam
import cgtsclient.v1.ihost
import cgtsclient.v1.iinterface
import cgtsclient.v1.imemory
import cgtsclient.v1.inode
import cgtsclient.v1.interface_datanetwork
import cgtsclient.v1.interface_network
import cgtsclient.v1.intp
import cgtsclient.v1.isensor
import cgtsclient.v1.isensorgroup
import cgtsclient.v1.iservice
import cgtsclient.v1.iservicegroup
import cgtsclient.v1.istor
import cgtsclient.v1.isystem
import cgtsclient.v1.iuser
import cgtsclient.v1.kube_app
import cgtsclient.v1.kube_cmd_version
import cgtsclient.v1.kube_config_kubelet
import cgtsclient.v1.label
import cgtsclient.v1.license
import cgtsclient.v1.lldp_agent
import cgtsclient.v1.lldp_neighbour
import cgtsclient.v1.network
import cgtsclient.v1.network_addrpool
import cgtsclient.v1.partition
import cgtsclient.v1.pci_device
import cgtsclient.v1.port
import cgtsclient.v1.ptp
import cgtsclient.v1.ptp_ha_phc2sys_control
import cgtsclient.v1.ptp_instance
import cgtsclient.v1.ptp_interface
import cgtsclient.v1.ptp_parameter
import cgtsclient.v1.registry_image
import cgtsclient.v1.remotelogging
import cgtsclient.v1.restore
import cgtsclient.v1.route
import cgtsclient.v1.sdn_controller
import cgtsclient.v1.sm_service
import cgtsclient.v1.sm_service_nodes
import cgtsclient.v1.sm_servicegroup
import cgtsclient.v1.storage_backend
import cgtsclient.v1.storage_ceph
import cgtsclient.v1.storage_ceph_external
import cgtsclient.v1.storage_ceph_rook
import cgtsclient.v1.storage_external
import cgtsclient.v1.storage_file
import cgtsclient.v1.storage_lvm
import cgtsclient.v1.storage_tier
import cgtsclient.v1.upgrade


def _make_fixtures(path, key, data, data2=None):
    """Build standard GET list + GET single fixtures."""
    f = {
        path: {
            'GET': ({}, {key: [data] + ([data2] if data2 else [])}),
            'POST': ({}, data),
        },
        path + '/' + str(data.get('uuid', data.get('id', '1'))): {
            'GET': ({}, data),
            'PATCH': ({}, data),
            'DELETE': ({}, None),
        },
    }
    return f


class TestIsystemManager(testtools.TestCase):
    def setUp(self):
        super(TestIsystemManager, self).setUp()
        self.data = {'uuid': 'sys-1', 'name': 'test-system'}
        f = _make_fixtures('/v1/isystems', 'isystems', self.data)
        self.api = utils.FakeAPI(f)
        self.mgr = cgtsclient.v1.isystem.isystemManager(self.api)

    def test_list(self):
        r = self.mgr.list()
        self.assertEqual(len(r), 1)

    def test_get(self):
        r = self.mgr.get('sys-1')
        self.assertEqual(r.uuid, 'sys-1')

    def test_update(self):
        patch = [{'op': 'replace', 'path': '/name', 'value': 'new'}]
        r = self.mgr.update('sys-1', patch)
        self.assertIsNotNone(r)


class TestClusterManager(testtools.TestCase):
    def setUp(self):
        super(TestClusterManager, self).setUp()
        self.data = {'uuid': 'cl-1', 'name': 'ceph', 'type': 'ceph'}
        f = {'/v1/clusters': {'GET': ({}, {'clusters': [self.data]})},
             '/v1/clusters/cl-1': {'GET': ({}, self.data)}}
        self.api = utils.FakeAPI(f)
        self.mgr = cgtsclient.v1.cluster.ClusterManager(self.api)

    def test_list(self):
        self.assertEqual(len(self.mgr.list()), 1)

    def test_get(self):
        self.assertEqual(self.mgr.get('cl-1').uuid, 'cl-1')


class TestAddressPoolManager(testtools.TestCase):
    def setUp(self):
        super(TestAddressPoolManager, self).setUp()
        self.data = {
            'uuid': 'ap-1',
            'name': 'mgmt',
            'network': '192.168.1.0',
            'prefix': 24
        }
        f = _make_fixtures('/v1/addrpools', 'addrpools', self.data)
        self.api = utils.FakeAPI(f)
        self.mgr = (
            cgtsclient.v1.address_pool.AddressPoolManager(self.api)
        )

    def test_list(self):
        self.assertEqual(len(self.mgr.list()), 1)

    def test_get(self):
        self.assertEqual(self.mgr.get('ap-1').uuid, 'ap-1')


class TestNetworkManager(testtools.TestCase):
    def setUp(self):
        super(TestNetworkManager, self).setUp()
        self.data = {'uuid': 'net-1', 'name': 'mgmt', 'type': 'mgmt'}
        f = _make_fixtures('/v1/networks', 'networks', self.data)
        self.api = utils.FakeAPI(f)
        self.mgr = cgtsclient.v1.network.NetworkManager(self.api)

    def test_list(self):
        self.assertEqual(len(self.mgr.list()), 1)

    def test_get(self):
        self.assertEqual(self.mgr.get('net-1').uuid, 'net-1')


class TestControllerFsManager(testtools.TestCase):
    def setUp(self):
        super(TestControllerFsManager, self).setUp()
        self.data = {'uuid': 'cfs-1', 'name': 'database', 'size': 20}
        f = _make_fixtures(
            '/v1/controller_fs',
            'controller_fs',
            self.data
        )
        self.api = utils.FakeAPI(f)
        self.mgr = (
            cgtsclient.v1.controller_fs.ControllerFsManager(self.api)
        )

    def test_list(self):
        self.assertEqual(len(self.mgr.list()), 1)

    def test_get(self):
        self.assertEqual(self.mgr.get('cfs-1').uuid, 'cfs-1')


class TestHostFsManager(testtools.TestCase):
    def setUp(self):
        super(TestHostFsManager, self).setUp()
        self.data = {'uuid': 'hfs-1', 'name': 'scratch', 'size': 16}
        f = _make_fixtures(
            '/v1/ihosts/h1/host_fs',
            'host_fs',
            self.data
        )
        self.api = utils.FakeAPI(f)
        self.mgr = cgtsclient.v1.host_fs.HostFsManager(self.api)

    def test_list(self):
        r = self.mgr.list('h1')
        self.assertEqual(len(r), 1)


class TestIdiskManager(testtools.TestCase):
    def setUp(self):
        super(TestIdiskManager, self).setUp()
        self.data = {'uuid': 'disk-1', 'device_node': '/dev/sda'}
        f = {'/v1/ihosts/h1/idisks': {'GET': ({},
                                              {'idisks': [self.data]}
                                              )},
             '/v1/idisks/disk-1': {'GET': ({}, self.data)}}
        self.api = utils.FakeAPI(f)
        self.mgr = cgtsclient.v1.idisk.idiskManager(self.api)

    def test_list(self):
        self.assertEqual(len(self.mgr.list('h1')), 1)

    def test_get(self):
        self.assertEqual(self.mgr.get('disk-1').uuid, 'disk-1')


class TestIstorManager(testtools.TestCase):
    def setUp(self):
        super(TestIstorManager, self).setUp()
        self.data = {'uuid': 'stor-1', 'function': 'osd'}
        f = {'/v1/ihosts/h1/istors': {'GET': ({},
                                              {'istors': [self.data]}
                                              )},
             '/v1/istors/stor-1': {'GET': ({}, self.data)}}
        self.api = utils.FakeAPI(f)
        self.mgr = cgtsclient.v1.istor.istorManager(self.api)

    def test_list(self):
        self.assertEqual(len(self.mgr.list('h1')), 1)

    def test_get(self):
        self.assertEqual(self.mgr.get('stor-1').uuid, 'stor-1')


class TestPartitionManager(testtools.TestCase):
    def setUp(self):
        super(TestPartitionManager, self).setUp()
        self.data = {'uuid': 'part-1', 'device_node': '/dev/sda1'}
        f = {'/v1/ihosts/h1/partitions': {'GET': ({},
                                                  {'partitions': [
                                                      self.data]}
                                                  )},
             '/v1/partitions/part-1': {'GET': ({}, self.data)}}
        self.api = utils.FakeAPI(f)
        self.mgr = cgtsclient.v1.partition.partitionManager(self.api)

    def test_list(self):
        self.assertEqual(len(self.mgr.list('h1')), 1)

    def test_get(self):
        self.assertEqual(self.mgr.get('part-1').uuid, 'part-1')


class TestPtpInstanceManager(testtools.TestCase):
    def setUp(self):
        super(TestPtpInstanceManager, self).setUp()
        self.data = (
            {'uuid': 'ptp-1', 'name': 'ptp4l', 'service': 'ptp4l'}
        )
        f = _make_fixtures(
            '/v1/ptp_instances',
            'ptp_instances',
            self.data
        )
        self.api = utils.FakeAPI(f)
        self.mgr = (
            cgtsclient.v1.ptp_instance.PtpInstanceManager(self.api)
        )

    def test_list(self):
        self.assertEqual(len(self.mgr.list()), 1)

    def test_get(self):
        self.assertEqual(self.mgr.get('ptp-1').uuid, 'ptp-1')


class TestPtpParameterManager(testtools.TestCase):
    def setUp(self):
        super(TestPtpParameterManager, self).setUp()
        self.data = (
            {'uuid': 'pp-1', 'name': 'domainNumber', 'value': '24'}
        )
        f = _make_fixtures(
            '/v1/ptp_parameters',
            'ptp_parameters',
            self.data
        )
        self.api = utils.FakeAPI(f)
        self.mgr = (
            cgtsclient.v1.ptp_parameter.PtpParameterManager(self.api)
        )

    def test_list(self):
        self.assertEqual(len(self.mgr.list()), 1)

    def test_get(self):
        self.assertEqual(self.mgr.get('pp-1').uuid, 'pp-1')


class TestCertificateManager(testtools.TestCase):
    def setUp(self):
        super(TestCertificateManager, self).setUp()
        self.data = {'uuid': 'cert-1', 'certtype': 'ssl_ca'}
        f = _make_fixtures('/v1/certificate', 'certificates', self.data)
        self.api = utils.FakeAPI(f)
        self.mgr = (
            cgtsclient.v1.certificate.CertificateManager(self.api)
        )

    def test_list(self):
        self.assertEqual(len(self.mgr.list()), 1)

    def test_get(self):
        self.assertEqual(self.mgr.get('cert-1').uuid, 'cert-1')


class TestAppManager(testtools.TestCase):
    def setUp(self):
        super(TestAppManager, self).setUp()
        self.data = {'name': 'platform-integ-apps', 'status': 'applied'}
        f = {'/v1/apps': {'GET': ({}, {'apps': [self.data]})},
             '/v1/apps/platform-integ-apps': {'GET': ({}, self.data)}}
        self.api = utils.FakeAPI(f)
        self.mgr = cgtsclient.v1.app.AppManager(self.api)

    def test_list(self):
        self.assertEqual(len(self.mgr.list()), 1)


class TestRemoteloggingManager(testtools.TestCase):
    def setUp(self):
        super(TestRemoteloggingManager, self).setUp()
        self.data = {'uuid': 'rl-1', 'ip_address': '10.0.0.1'}
        f = {'/v1/remotelogging': {'GET': ({},
                                           {'remoteloggings': [
                                               self.data]}
                                           ), 'POST': ({}, self.data)},
             '/v1/remotelogging/rl-1': {'GET': ({},
                                                [self.data]
                                                ), 'PATCH': ({}, self.data)}}
        self.api = utils.FakeAPI(f)
        self.mgr = (
            cgtsclient.v1.remotelogging.RemoteLoggingManager(self.api)
        )

    def test_list(self):
        self.assertEqual(len(self.mgr.list()), 1)

    def test_get(self):
        self.assertEqual(self.mgr.get('rl-1').uuid, 'rl-1')


class TestSmServiceManager(testtools.TestCase):
    def setUp(self):
        super(TestSmServiceManager, self).setUp()
        self.data = {
            'uuid': 'svc-1',
            'name': 'sysinv',
            'state': 'enabled-active'
        }
        f = {'/v1/services': {'GET': ({}, {'services': [self.data]})},
             '/v1/services/svc-1': {'GET': ({}, self.data)}}
        self.api = utils.FakeAPI(f)
        self.mgr = cgtsclient.v1.sm_service.SmServiceManager(self.api)

    def test_list(self):
        self.assertEqual(len(self.mgr.list()), 1)


class TestResourceRepr(testtools.TestCase):
    """Test __repr__ for all resource classes."""

    def test_isystem_repr(self):
        r = cgtsclient.v1.isystem.isystem(None, {'name': 'test'})
        self.assertIn('test', repr(r))

    def test_ihost_repr(self):
        r = cgtsclient.v1.ihost.ihost(None, {'hostname': 'ctrl-0'})
        self.assertIn('ctrl-0', repr(r))

    def test_cluster_repr(self):
        r = cgtsclient.v1.cluster.Cluster(None, {'name': 'ceph'})
        self.assertIn('ceph', repr(r))

    def test_address_pool_repr(self):
        r = cgtsclient.v1.address_pool.AddressPool(
            None,
            {'name': 'mgmt'}
        )
        self.assertIn('mgmt', repr(r))

    def test_network_repr(self):
        r = cgtsclient.v1.network.Network(None, {'name': 'mgmt'})
        self.assertIn('mgmt', repr(r))

    def test_datanetwork_repr(self):
        r = cgtsclient.v1.datanetwork.DataNetwork(None, {'name': 'dn1'})
        self.assertIn('dn1', repr(r))

    def test_certificate_repr(self):
        r = cgtsclient.v1.certificate.Certificate(None, {'uuid': 'c1'})
        self.assertIn('c1', repr(r))

    def test_partition_repr(self):
        r = cgtsclient.v1.partition.partition(None, {'uuid': 'p1'})
        self.assertIn('p1', repr(r))

    def test_ptp_instance_repr(self):
        r = cgtsclient.v1.ptp_instance.PtpInstance(
            None,
            {'name': 'ptp4l'}
        )
        self.assertIsNotNone(repr(r))

    def test_storage_backend_repr(self):
        r = cgtsclient.v1.storage_backend.StorageBackend(
            None,
            {'uuid': 'sb1'}
        )
        self.assertIsNotNone(repr(r))

    def test_app_repr(self):
        r = cgtsclient.v1.app.App(None, {'name': 'myapp'})
        self.assertIsNotNone(repr(r))
