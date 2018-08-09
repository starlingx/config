# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


"""Tests for manipulating Nodes via the DB API"""

from sysinv.openstack.common import uuidutils

from sysinv.common import constants
from sysinv.common import exception
from sysinv.db import api as dbapi
from sysinv.tests.db import base
from sysinv.tests.db import utils


class DbNodeTestCase(base.DbTestCase):

    def setUp(self):
        super(DbNodeTestCase, self).setUp()
        self.dbapi = dbapi.get_instance()
        self.system = utils.create_test_isystem()
        self.load = utils.create_test_load()

    def _create_test_ihost(self, **kwargs):
        # ensure the system ID for proper association
        kwargs['forisystemid'] = self.system['id']
        n = utils.get_test_ihost(**kwargs)
        self.dbapi.ihost_create(n)
        return n

    def _create_many_test_ihosts(self):
        uuids = []
        for i in xrange(1, 6):
            n = self._create_test_ihost(id=i, uuid=uuidutils.generate_uuid())
            uuids.append(n['uuid'])
        uuids.sort()
        return uuids

    def test_create_ihost(self):
        self._create_test_ihost()

    def test_get_ihost_by_id(self):
        n = self._create_test_ihost()
        res = self.dbapi.ihost_get(n['id'])
        self.assertEqual(n['uuid'], res['uuid'])

    def test_get_ihost_by_hostname(self):
        hostname_test = "hostnamesysinv"
        n = self._create_test_ihost(hostname=hostname_test)
        res = self.dbapi.ihost_get_by_hostname(hostname_test)
        self.assertEqual(n['hostname'], res['hostname'])

    def test_update_ihost(self):
        n = self._create_test_ihost()

        old_location = n['location']
        new_location = {'foo': 'bar'}
        self.assertNotEqual(old_location, new_location)

        res = self.dbapi.ihost_update(n['id'], {'location': new_location})
        self.assertEqual(new_location, res['location'])

    def test_update_ihost_administrative(self):
        n = self._create_test_ihost()

        old_state = n['administrative']
        new_state = "unlocked"
        self.assertNotEqual(old_state, new_state)

        res = self.dbapi.ihost_update(n['id'], {'administrative': new_state})
        self.assertEqual(new_state, res['administrative'])

    def test_update_ihost_operational(self):
        n = self._create_test_ihost()

        old_state = n['operational']
        new_state = "enabled"
        self.assertNotEqual(old_state, new_state)

        res = self.dbapi.ihost_update(n['id'], {'operational': new_state})
        self.assertEqual(new_state, res['operational'])

    def test_update_ihost_availability(self):
        n = self._create_test_ihost()

        old_state = n['availability']
        new_state = "available"
        self.assertNotEqual(old_state, new_state)

        res = self.dbapi.ihost_update(n['id'], {'availability': new_state})
        self.assertEqual(new_state, res['availability'])

    def test_destroy_ihost(self):
        n = self._create_test_ihost()

        self.dbapi.ihost_destroy(n['id'])
        self.assertRaises(exception.ServerNotFound,
                          self.dbapi.ihost_get, n['id'])

    def test_create_cpuToplogy_on_a_server(self):
        n = self._create_test_ihost()
        forihostid = n['id']

        p = self.dbapi.icpu_create(forihostid,
                utils.get_test_icpu(forinodeid=3, cpu=2))
        self.assertEqual(n['id'], p['forihostid'])

    def test_create_memoryToplogy_on_a_server_and_cpu(self):
        hmemsize = 1000
        n = self._create_test_ihost()

        forihostid = n['id']

        p = self.dbapi.icpu_create(forihostid,
                utils.get_test_icpu(forinodeid=1, cpu=3))
        self.assertEqual(n['id'], p['forihostid'])

        forSocketNuma = p['forinodeid']

        m = self.dbapi.imemory_create(forihostid,
                utils.get_test_imemory(Hugepagesize=hmemsize,
                        forinodeid=forSocketNuma))
        self.assertEqual(n['id'], m['forihostid'])
        self.assertEqual(p['forinodeid'], m['forinodeid'])

    def test_create_networkPort_on_a_server(self):
        n = self._create_test_ihost()

        forihostid = n['id']

        p = self.dbapi.ethernet_port_create(forihostid,
                utils.get_test_port(name='eth0', pciaddr="00:03.0"))
        self.assertEqual(n['id'], p['host_id'])

    def test_create_storageVolume_on_a_server(self):
        n = self._create_test_ihost()

        forihostid = n['id']
        # diskType= '{"diskType":"SAS"}'))
        p = self.dbapi.idisk_create(forihostid,
                utils.get_test_idisk(deviceId='sda0'))
        self.assertEqual(n['id'], p['forihostid'])

    # Storage Backend: Base class
    def _create_test_storage_backend(self, **kwargs):
        kwargs['forisystemid'] = self.system['id']
        n = utils.get_test_storage_backend(**kwargs)
        self.dbapi.storage_backend_create(n)
        self.assertRaises(exception.InvalidParameterValue,
                          self.dbapi.storage_backend_create, n)

    def _create_test_storage_backend_with_ceph(self, **kwargs):
        kwargs['forisystemid'] = self.system['id']
        kwargs['backend'] = constants.SB_TYPE_CEPH
        n = utils.get_test_storage_backend(**kwargs)
        self.dbapi.storage_backend_create(n)
        return n

    def test_storage_backend_get_by_backend(self):
        n = self._create_test_storage_backend_with_ceph()
        res = self.dbapi.storage_backend_get(n['backend'])
        self.assertEqual(n['backend'], res['backend'])

    def _create_test_storage_backend_with_file(self, **kwargs):
        kwargs['forisystemid'] = self.system['id']
        kwargs['backend'] = constants.SB_TYPE_FILE
        n = utils.get_test_storage_backend(**kwargs)
        self.dbapi.storage_backend_create(n)
        return n

    def test_storage_backend_get_by_uuid(self):
        n = self._create_test_storage_backend_with_file()
        res = self.dbapi.storage_backend_get(n['uuid'])
        self.assertEqual(n['uuid'], res['uuid'])

    def _create_test_storage_backend_with_lvm(self, **kwargs):
        kwargs['forisystemid'] = self.system['id']
        kwargs['backend'] = constants.SB_TYPE_LVM
        n = utils.get_test_storage_backend(**kwargs)
        self.dbapi.storage_backend_create(n)
        return n

    def test_storage_backend_get_by_id(self):
        n = self._create_test_storage_backend_with_lvm()
        n['id'] = 1
        res = self.dbapi.storage_backend_get(n['id'])
        self.assertEqual(n['id'], res['id'])

    def test_storage_backend_get_list(self):
        c = self._create_test_storage_backend_with_ceph()
        f = self._create_test_storage_backend_with_file()
        ll = self._create_test_storage_backend_with_lvm()
        res = self.dbapi.storage_backend_get_list(sort_key='backend')
        self.assertEqual(len(res), 3)
        self.assertEqual(c['backend'], res[0]['backend'])
        self.assertEqual(f['backend'], res[1]['backend'])
        self.assertEqual(ll['backend'], res[2]['backend'])

    def test_storage_backend_get_by_isystem(self):
        c = self._create_test_storage_backend_with_ceph()
        f = self._create_test_storage_backend_with_file()
        ll = self._create_test_storage_backend_with_lvm()
        res = self.dbapi.storage_backend_get_by_isystem(self.system['id'],
                                                        sort_key='backend')
        self.assertEqual(len(res), 3)
        self.assertEqual(c['backend'], res[0]['backend'])
        self.assertEqual(f['backend'], res[1]['backend'])
        self.assertEqual(ll['backend'], res[2]['backend'])

    def test_storage_backend_get_by_isystem_none(self):
        self._create_test_storage_backend_with_ceph()
        self._create_test_storage_backend_with_file()
        self._create_test_storage_backend_with_lvm()
        self.assertRaises(exception.ServerNotFound,
                          self.dbapi.storage_backend_get_by_isystem,
                          self.system['id'] + 1)

    def test_storage_backend_update(self):
        c = self._create_test_storage_backend_with_ceph()
        f = self._create_test_storage_backend_with_file()
        ll = self._create_test_storage_backend_with_lvm()
        res = self.dbapi.storage_backend_get_list(sort_key='backend')
        self.assertEqual(len(res), 3)
        self.assertEqual(c['backend'], res[0]['backend'])
        self.assertEqual(f['backend'], res[1]['backend'])
        self.assertEqual(ll['backend'], res[2]['backend'])

        values = {}
        for k in c:
            values.update({k: res[0][k]})
        values['services'] = 'cinder, glance, swift'

        upd = self.dbapi.storage_backend_update(res[0]['id'], values)
        self.assertEqual(values['services'], upd['services'])

        values = {}
        for k in f:
            values.update({k: res[1][k]})
            values['services'] = 'glance'

        upd = self.dbapi.storage_backend_update(res[1]['id'], values)
        self.assertEqual(values['services'], upd['services'])

        values = {}
        for k in ll:
            values.update({k: res[2][k]})
            values['services'] = 'cinder'

        upd = self.dbapi.storage_backend_update(res[2]['id'], values)
        self.assertEqual(values['services'], upd['services'])

    # File Storage Backend
    def _create_test_storage_backend_file(self, **kwargs):
        kwargs['forisystemid'] = self.system['id']
        n = utils.get_test_file_storage_backend(**kwargs)
        self.dbapi.storage_file_create(n)
        return n

    def test_create_storage_backend_file(self):
        self._create_test_storage_backend_file()

    def test_storage_file_get_by_uuid(self):
        n = self._create_test_storage_backend_file()
        res = self.dbapi.storage_file_get(n['uuid'])
        self.assertEqual(n['uuid'], res['uuid'])

    def test_storage_file_get_by_id(self):
        n = self._create_test_storage_backend_file()
        res = self.dbapi.storage_file_get(n['id'])
        self.assertEqual(n['id'], res['id'])

    def test_storage_file_get_by_backend(self):
        n = self._create_test_storage_backend_file()
        res = self.dbapi.storage_file_get(n['backend'])
        self.assertEqual(n['backend'], res['backend'])

    def test_storage_file_get_list(self):
        n = self._create_test_storage_backend_file()
        res = self.dbapi.storage_file_get_list()
        self.assertEqual(len(res), 1)
        self.assertEqual(n['backend'], res[0]['backend'])
        self.assertEqual(n['uuid'], res[0]['uuid'])

    def test_storage_file_update(self):
        n = self._create_test_storage_backend_file()
        res = self.dbapi.storage_file_get(n['backend'])
        self.assertEqual(n['backend'], res['backend'])

        values = {}
        for k in n:
            values.update({k: res[k]})
            values['services'] = 'glance'

        upd = self.dbapi.storage_file_update(res['id'], values)
        self.assertEqual(values['services'], upd['services'])

    # LVM Storage Backend
    def _create_test_storage_backend_lvm(self, **kwargs):
        kwargs['forisystemid'] = self.system['id']
        n = utils.get_test_lvm_storage_backend(**kwargs)
        self.dbapi.storage_lvm_create(n)
        return n

    def test_create_storage_backend_lvm(self):
        self._create_test_storage_backend_lvm()

    def test_storage_lvm_get_by_uuid(self):
        n = self._create_test_storage_backend_lvm()
        res = self.dbapi.storage_lvm_get(n['uuid'])
        self.assertEqual(n['uuid'], res['uuid'])

    def test_storage_lvm_get_by_id(self):
        n = self._create_test_storage_backend_lvm()
        res = self.dbapi.storage_lvm_get(n['id'])
        self.assertEqual(n['id'], res['id'])

    def test_storage_lvm_get_by_backend(self):
        n = self._create_test_storage_backend_lvm()
        res = self.dbapi.storage_lvm_get(n['backend'])
        self.assertEqual(n['backend'], res['backend'])

    def test_storage_lvm_get_list(self):
        n = self._create_test_storage_backend_lvm()
        res = self.dbapi.storage_lvm_get_list()
        self.assertEqual(len(res), 1)
        self.assertEqual(n['backend'], res[0]['backend'])
        self.assertEqual(n['uuid'], res[0]['uuid'])

    def test_storage_lvm_update(self):
        n = self._create_test_storage_backend_lvm()
        res = self.dbapi.storage_lvm_get(n['backend'])
        self.assertEqual(n['backend'], res['backend'])

        values = {}
        for k in n:
            values.update({k: res[k]})
            values['services'] = 'cinder'

        upd = self.dbapi.storage_file_update(res['id'], values)
        self.assertEqual(values['services'], upd['services'])

    # Ceph Storage Backend
    def _create_test_storage_backend_ceph(self, **kwargs):
        kwargs['forisystemid'] = self.system['id']
        t = utils.get_test_storage_tier()
        kwargs['tier_id'] = t['id']
        n = utils.get_test_ceph_storage_backend(**kwargs)
        self.dbapi.storage_ceph_create(n)
        return n

    def test_create_storage_backend_ceph(self):
        self._create_test_storage_backend_ceph()

    def test_storage_ceph_get_by_uuid(self):
        n = self._create_test_storage_backend_ceph()
        res = self.dbapi.storage_ceph_get(n['uuid'])
        self.assertEqual(n['uuid'], res['uuid'])

    def test_storage_ceph_get_by_id(self):
        n = self._create_test_storage_backend_ceph()
        res = self.dbapi.storage_ceph_get(n['id'])
        self.assertEqual(n['id'], res['id'])

    def test_storage_ceph_get_by_backend(self):
        n = self._create_test_storage_backend_ceph()
        res = self.dbapi.storage_ceph_get(n['backend'])
        self.assertEqual(n['backend'], res['backend'])

    def test_storage_ceph_get_list(self):
        n = self._create_test_storage_backend_ceph()
        res = self.dbapi.storage_ceph_get_list()
        self.assertEqual(len(res), 1)
        self.assertEqual(n['backend'], res[0]['backend'])
        self.assertEqual(n['uuid'], res[0]['uuid'])

    def test_storage_ceph_update(self):
        n = self._create_test_storage_backend_ceph()
        res = self.dbapi.storage_ceph_get(n['backend'])
        self.assertEqual(n['backend'], res['backend'])

        values = {}
        for k in n:
            values.update({k: res[k]})
        values['services'] = 'cinder, glance, swift'

        upd = self.dbapi.storage_ceph_update(res['id'], values)
        self.assertEqual(values['services'], upd['services'])
