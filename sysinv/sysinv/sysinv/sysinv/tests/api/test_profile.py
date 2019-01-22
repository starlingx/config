# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# Copyright (c) 2017 Wind River Systems, Inc.
#

import mock
from six.moves import http_client

from sysinv.common import constants
from sysinv.common import utils as cutils
from sysinv.db import api as dbapi
from sysinv.tests.api import base
from sysinv.tests.db import utils as dbutils

HEADER = {'User-Agent': 'sysinv'}


class ProfileTestCase(base.FunctionalTest):

    def setUp(self):
        super(ProfileTestCase, self).setUp()
        self.dbapi = dbapi.get_instance()
        self.system = dbutils.create_test_isystem()
        self.load = dbutils.create_test_load()
        self.controller = dbutils.create_test_ihost(
            id='1',
            uuid=None,
            forisystemid=self.system.id,
            hostname='controller-0',
            personality=constants.CONTROLLER,
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED,
        )
        self.worker = dbutils.create_test_ihost(
            id='2',
            uuid=None,
            forisystemid=self.system.id,
            hostname='worker-0',
            personality=constants.WORKER,
            subfunctions=constants.WORKER,
            mgmt_mac='01:02.03.04.05.C0',
            mgmt_ip='192.168.24.12',
            invprovision=constants.PROVISIONED,
        )
        self.profile = {
            'profilename': 'profile-node1',
            'ihost_uuid': self.controller.uuid,
        }
        self.ctrlnode = self.dbapi.inode_create(self.controller.id,
                                                dbutils.get_test_node(id=1))
        self.ctrlcpu = self.dbapi.icpu_create(
            self.controller.id,
            dbutils.get_test_icpu(id=1, cpu=0,
                                  forihostid=self.controller.id,
                                  forinodeid=self.ctrlnode.id,))

        self.ctrlif = dbutils.create_test_interface(
            forihostid=self.controller.id)
        self.port1 = dbutils.create_test_ethernet_port(
            id='1', name=self.ctrlif.ifname, host_id=self.controller.id,
            interface_id=self.ctrlif.id, mac='08:00:27:43:60:11')

        self.ctrlmemory = self.dbapi.imemory_create(
            self.controller.id,
            dbutils.get_test_imemory(id=1,
                                     hugepages_configured=True,
                                     forinodeid=self.ctrlcpu.forinodeid))

        self.compnode = self.dbapi.inode_create(self.worker.id,
                                                dbutils.get_test_node(id=2))
        self.compcpu = self.dbapi.icpu_create(
            self.worker.id,
            dbutils.get_test_icpu(id=5, cpu=3,
                                  forinodeid=self.compnode.id,
                                  forihostid=self.worker.id))
        self.compmemory = self.dbapi.imemory_create(
            self.worker.id,
            dbutils.get_test_imemory(id=2, Hugepagesize=constants.MIB_1G,
                                     forinodeid=self.compcpu.forinodeid))

        self.disk = self.dbapi.idisk_create(
            self.worker.id,
            dbutils.get_test_idisk(device_node='/dev/sdb',
                                   device_type=constants.DEVICE_TYPE_HDD))
        self.lvg = self.dbapi.ilvg_create(
            self.worker.id,
            dbutils.get_test_lvg(lvm_vg_name=constants.LVG_NOVA_LOCAL))
        self.pv = self.dbapi.ipv_create(
            self.worker.id,
            dbutils.get_test_pv(lvm_vg_name=constants.LVG_NOVA_LOCAL,
                                disk_or_part_uuid=self.disk.uuid))

    def _get_path(self, path=None):
        if path:
            return '/iprofile/' + path
        else:
            return '/iprofile'


class ProfileCreateTestCase(ProfileTestCase):

    def setUp(self):
        super(ProfileCreateTestCase, self).setUp()

    def create_profile(self, profiletype):
        self.profile["profiletype"] = profiletype
        response = self.post_json('%s' % self._get_path(), self.profile)
        self.assertEqual(http_client.OK, response.status_int)

    def test_create_cpu_success(self):
        self.profile["profiletype"] = constants.PROFILE_TYPE_CPU
        response = self.post_json('%s' % self._get_path(), self.profile)
        self.assertEqual(http_client.OK, response.status_int)

    def test_create_interface_success(self):
        self.profile["profiletype"] = constants.PROFILE_TYPE_INTERFACE
        response = self.post_json('%s' % self._get_path(), self.profile)
        self.assertEqual(http_client.OK, response.status_int)

    def test_create_memory_success(self):
        self.profile["profiletype"] = constants.PROFILE_TYPE_MEMORY
        self.profile["ihost_uuid"] = self.worker.uuid
        response = self.post_json('%s' % self._get_path(), self.profile)
        self.assertEqual(http_client.OK, response.status_int)

    def test_create_storage_success(self):
        self.profile["profiletype"] = constants.PROFILE_TYPE_STORAGE
        self.profile["ihost_uuid"] = self.worker.uuid
        response = self.post_json('%s' % self._get_path(), self.profile)
        self.assertEqual(http_client.OK, response.status_int)


class ProfileDeleteTestCase(ProfileTestCase):
    def setUp(self):
        super(ProfileDeleteTestCase, self).setUp()

    def test_delete_cpu_success(self):
        self.profile["profiletype"] = constants.PROFILE_TYPE_CPU
        post_response = self.post_json('%s' % self._get_path(), self.profile)
        profile_data = self.get_json('%s' % self._get_path())
        cpuprofile_data = self.get_json(
            '%s' % self._get_path(profile_data['iprofiles'][0]['uuid']))
        self.assertEqual(post_response.json['uuid'], cpuprofile_data['uuid'])
        self.delete(
            '%s/%s' % (self._get_path(), post_response.json['uuid']))

    def test_delete_interface_success(self):
        self.profile["profiletype"] = constants.PROFILE_TYPE_INTERFACE
        post_response = self.post_json('%s' % self._get_path(), self.profile)
        profile_data = self.get_json('%s' % self._get_path())
        ifprofile_data = self.get_json(
            '%s' % self._get_path(profile_data['iprofiles'][0]['uuid']))
        self.assertEqual(post_response.json['uuid'], ifprofile_data['uuid'])
        self.delete(
            '%s/%s' % (self._get_path(), post_response.json['uuid']))

    def test_delete_memory_success(self):
        self.profile["profiletype"] = constants.PROFILE_TYPE_MEMORY
        post_response = self.post_json('%s' % self._get_path(), self.profile)
        profile_data = self.get_json('%s' % self._get_path())
        memprofile_data = self.get_json(
            '%s' % self._get_path(profile_data['iprofiles'][0]['uuid']))
        self.assertEqual(post_response.json['uuid'], memprofile_data['uuid'])
        self.delete(
            '%s/%s' % (self._get_path(), post_response.json['uuid']))

    def test_delete_storage_success(self):
        self.profile["profiletype"] = constants.PROFILE_TYPE_STORAGE
        self.profile["ihost_uuid"] = self.worker.uuid
        post_response = self.post_json('%s' % self._get_path(), self.profile)
        profile_data = self.get_json('%s' % self._get_path())
        storprofile_data = self.get_json(
            '%s' % self._get_path(profile_data['iprofiles'][0]['uuid']))
        self.assertEqual(post_response.json['uuid'], storprofile_data['uuid'])
        self.delete(
            '%s/%s' % (self._get_path(), post_response.json['uuid']))


class ProfileShowTestCase(ProfileTestCase):
    def setUp(self):
        super(ProfileShowTestCase, self).setUp()

    def test_show_cpu_success(self):
        self.profile["profiletype"] = constants.PROFILE_TYPE_CPU
        self.post_json('%s' % self._get_path(), self.profile)
        list_data = self.get_json('%s' % self._get_path())
        show_data = self.get_json(
            '%s/icpus' % self._get_path(list_data['iprofiles'][0]['uuid']))
        self.assertEqual(self.ctrlcpu.allocated_function,
                         show_data['icpus'][0]['allocated_function'])

    def test_show_interface_success(self):
        self.profile["profiletype"] = constants.PROFILE_TYPE_INTERFACE
        self.post_json('%s' % self._get_path(), self.profile)
        list_data = self.get_json('%s' % self._get_path())
        show_data = self.get_json('%s/iinterfaces' % self._get_path(
            list_data['iprofiles'][0]['uuid']))
        self.assertEqual(self.ctrlif.ifname,
                         show_data['iinterfaces'][0]['ifname'])
        self.assertEqual(self.ctrlif.iftype,
                         show_data['iinterfaces'][0]['iftype'])

    @mock.patch.object(cutils, 'is_virtual')
    def test_show_memory_success(self, mock_is_virtual):
        mock_is_virtual.return_value = True
        self.profile["profiletype"] = constants.PROFILE_TYPE_MEMORY
        self.post_json('%s' % self._get_path(), self.profile)
        list_data = self.get_json('%s' % self._get_path())
        show_data = self.get_json(
            '%s/imemorys' % self._get_path(list_data['iprofiles'][0]['uuid']))
        self.assertEqual(self.ctrlmemory.platform_reserved_mib,
                         show_data['imemorys'][0]['platform_reserved_mib'])
        self.assertEqual(self.ctrlmemory.vm_hugepages_nr_2M,
                         show_data['imemorys'][0]['vm_hugepages_nr_2M_pending'])
        self.assertEqual(self.ctrlmemory.vm_hugepages_nr_1G,
                         show_data['imemorys'][0]['vm_hugepages_nr_1G_pending'])

    def test_show_storage_success(self):
        self.profile["profiletype"] = constants.PROFILE_TYPE_STORAGE
        self.profile["ihost_uuid"] = self.worker.uuid
        self.post_json('%s' % self._get_path(), self.profile)
        list_data = self.get_json('%s' % self._get_path())
        profile_uuid = list_data['iprofiles'][0]['uuid']
        show_data = self.get_json(
            '%s/idisks' % self._get_path(profile_uuid))
        self.assertEqual(self.disk.device_path,
                         show_data['idisks'][0]['device_path'])
        show_data = self.get_json(
            '%s/ipvs' % self._get_path(profile_uuid))
        self.assertEqual(self.pv.pv_type,
                         show_data['ipvs'][0]['pv_type'])
        show_data = self.get_json(
            '%s/ilvgs' % self._get_path(profile_uuid))
        self.assertEqual(self.lvg.lvm_vg_name,
                         show_data['ilvgs'][0]['lvm_vg_name'])


class ProfileListTestCase(ProfileTestCase):
    def setUp(self):
        super(ProfileListTestCase, self).setUp()

    def test_list_cpu_success(self):
        self.profile["profiletype"] = constants.PROFILE_TYPE_CPU
        post_response = self.post_json('%s' % self._get_path(), self.profile)
        list_data = self.get_json('%s' % self._get_path())
        self.assertEqual(post_response.json['uuid'],
                         list_data['iprofiles'][0]['uuid'])

    def test_list_interface_success(self):
        self.profile["profiletype"] = constants.PROFILE_TYPE_INTERFACE
        post_response = self.post_json('%s' % self._get_path(), self.profile)
        list_data = self.get_json('%s' % self._get_path())
        self.assertEqual(post_response.json['uuid'],
                         list_data['iprofiles'][0]['uuid'])

    def test_list_memory_success(self):
        self.profile["profiletype"] = constants.PROFILE_TYPE_MEMORY
        post_response = self.post_json('%s' % self._get_path(), self.profile)
        list_data = self.get_json('%s' % self._get_path())
        self.assertEqual(post_response.json['uuid'],
                         list_data['iprofiles'][0]['uuid'])

    def test_list_storage_success(self):
        self.profile["profiletype"] = constants.PROFILE_TYPE_STORAGE
        self.profile["ihost_uuid"] = self.worker.uuid
        post_response = self.post_json('%s' % self._get_path(), self.profile)
        list_data = self.get_json('%s' % self._get_path())
        self.assertEqual(post_response.json['uuid'],
                         list_data['iprofiles'][0]['uuid'])


class ProfileApplyTestCase(ProfileTestCase):
    def setUp(self):
        super(ProfileApplyTestCase, self).setUp()

    def test_apply_cpu_success(self):
        self.profile["profiletype"] = constants.PROFILE_TYPE_CPU
        response = self.post_json('%s' % self._get_path(), self.profile)
        self.assertEqual(http_client.OK, response.status_int)
        list_data = self.get_json('%s' % self._get_path())
        profile_uuid = list_data['iprofiles'][0]['uuid']
        result = self.patch_dict_json('/ihosts/%s' % self.controller.id,
                                      headers=HEADER,
                                      action=constants.APPLY_PROFILE_ACTION,
                                      iprofile_uuid=profile_uuid)
        self.assertEqual(http_client.OK, result.status_int)

        hostcpu_r = self.get_json(
            '/ihosts/%s/icpus' % self.worker.uuid)
        profile_r = self.get_json(
            '%s/icpus' % self._get_path(profile_uuid))
        self.assertEqual(hostcpu_r['icpus'][0]['allocated_function'],
                         profile_r['icpus'][0]['allocated_function'])

    @mock.patch.object(cutils, 'is_virtual')
    def test_apply_memory_success(self, mock_is_virtual):
        mock_is_virtual.return_value = True
        self.profile["profiletype"] = constants.PROFILE_TYPE_MEMORY
        self.profile["ihost_uuid"] = self.worker.uuid
        response = self.post_json('%s' % self._get_path(), self.profile)
        self.assertEqual(http_client.OK, response.status_int)

        list_data = self.get_json('%s' % self._get_path())
        profile_uuid = list_data['iprofiles'][0]['uuid']
        result = self.patch_dict_json('/ihosts/%s' % self.worker.id,
                                       headers=HEADER,
                                       action=constants.APPLY_PROFILE_ACTION,
                                       iprofile_uuid=profile_uuid)
        self.assertEqual(http_client.OK, result.status_int)

        hostmem_r = self.get_json(
            '/ihosts/%s/imemorys' % self.worker.uuid)
        profile_r = self.get_json(
            '%s/imemorys' % self._get_path(profile_uuid))
        self.assertEqual(hostmem_r['imemorys'][0]['platform_reserved_mib'],
                         profile_r['imemorys'][0]['platform_reserved_mib'])
        self.assertEqual(hostmem_r['imemorys'][0]['vm_hugepages_nr_2M_pending'],
                         profile_r['imemorys'][0]['vm_hugepages_nr_2M_pending'])
        self.assertEqual(hostmem_r['imemorys'][0]['vm_hugepages_nr_1G_pending'],
                         profile_r['imemorys'][0]['vm_hugepages_nr_1G_pending'])
        self.assertEqual(hostmem_r['imemorys'][0]['vswitch_hugepages_reqd'],
                         profile_r['imemorys'][0]['vswitch_hugepages_reqd'])

    def test_apply_storage_success(self):
        self.profile["profiletype"] = constants.PROFILE_TYPE_LOCAL_STORAGE
        self.profile["ihost_uuid"] = self.worker.uuid
        response = self.post_json('%s' % self._get_path(), self.profile)
        self.assertEqual(http_client.OK, response.status_int)

        list_data = self.get_json('%s' % self._get_path())
        profile_uuid = list_data['iprofiles'][0]['uuid']

        # Delete Physical volume and disassociate it from disk
        self.delete('/ipvs/%s' % self.pv.uuid)
        self.dbapi.idisk_update(self.disk.uuid,
                                {'foripvid': None, 'foristorid': None})
        # Delete Local Volume
        self.delete('/ilvgs/%s' % self.lvg.uuid)

        # Apply storage profile
        result = self.patch_dict_json('/ihosts/%s' % self.worker.id,
                                      headers=HEADER,
                                      action=constants.APPLY_PROFILE_ACTION,
                                      iprofile_uuid=profile_uuid)
        self.assertEqual(http_client.OK, result.status_int)

        hostdisk_r = self.get_json(
            '/ihosts/%s/idisks' % self.worker.uuid)
        profile_r = self.get_json(
            '%s/idisks' % self._get_path(profile_uuid))
        self.assertEqual(hostdisk_r['idisks'][0]['device_path'],
                         profile_r['idisks'][0]['device_path'])

        hostpv_r = self.get_json(
            '/ihosts/%s/ipvs' % self.worker.uuid)
        profile_r = self.get_json(
            '%s/ipvs' % self._get_path(profile_uuid))
        self.assertEqual(hostpv_r['ipvs'][1]['pv_type'],
                         profile_r['ipvs'][0]['pv_type'])
        if not profile_r['ipvs'][0].get('disk_or_part_device_path'):
            self.assertEqual(hostpv_r['ipvs'][1]['lvm_pv_name'],
                             profile_r['ipvs'][0]['lvm_pv_name'])

        hostlvg_r = self.get_json(
            '/ihosts/%s/ilvgs' % self.worker.uuid)
        profile_r = self.get_json(
            '%s/ilvgs' % self._get_path(profile_uuid))
        self.assertEqual(hostlvg_r['ilvgs'][0]['lvm_vg_name'],
                         profile_r['ilvgs'][0]['lvm_vg_name'])
