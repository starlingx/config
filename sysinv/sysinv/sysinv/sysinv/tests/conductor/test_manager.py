# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8

# Copyright 2013 Hewlett-Packard Development Company, L.P.
# Copyright 2013 International Business Machines Corporation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#

"""Test class for Sysinv ManagerService."""

from sysinv.common import exception
from sysinv.conductor import manager
from sysinv.db import api as dbapi
from sysinv.openstack.common import context
from sysinv.tests.db import base
from sysinv.tests.db import utils


class ManagerTestCase(base.DbTestCase):

    def setUp(self):
        super(ManagerTestCase, self).setUp()
        self.service = manager.ConductorManager('test-host', 'test-topic')
        self.service.dbapi = dbapi.get_instance()
        self.context = context.get_admin_context()
        self.dbapi = dbapi.get_instance()
        self.system = utils.create_test_isystem()
        self.load = utils.create_test_load()

    def _create_test_ihost(self, **kwargs):
        # ensure the system ID for proper association
        kwargs['forisystemid'] = self.system['id']
        ihost_dict = utils.get_test_ihost(**kwargs)
        ihost = self.dbapi.ihost_create(ihost_dict)
        return ihost

    def test_create_ihost(self):
        ihost_dict = {'mgmt_mac': '00:11:22:33:44:55',
                      'mgmt_ip': '1.2.3.4'}

        self.service.start()
        res = self.service.create_ihost(self.context, ihost_dict)
        self.assertEqual(res['mgmt_mac'], '00:11:22:33:44:55')
        self.assertEqual(res['mgmt_ip'], '1.2.3.4')

    def test_create_duplicate_ihost(self):
        ihost_dict = {'mgmt_mac': '00:11:22:33:44:55',
                      'mgmt_ip': '1.2.3.4'}

        self.service.start()
        # Create first ihost
        res1 = self.service.create_ihost(self.context, ihost_dict)
        # Update the serialid
        res1['serialid'] = '1234567890abc'
        res1 = self.service.update_ihost(self.context, res1)

        # Attempt to create duplicate ihost
        res2 = self.service.create_ihost(self.context, ihost_dict)

        # Verify that original ihost was returned
        self.assertEqual(res1['serialid'], res2['serialid'])

    def test_create_ihost_without_mac(self):
        ihost_dict = {'mgmt_ip': '1.2.3.4'}

        self.assertRaises(exception.SysinvException,
                          self.service.create_ihost,
                          self.context,
                          ihost_dict)

        # verify create did not happen
        res = self.dbapi.ihost_get_list()
        self.assertEqual(len(res), 0)

    def test_create_ihost_without_ip(self):
        ihost_dict = {'mgmt_mac': '00:11:22:33:44:55'}

        self.service.start()
        self.service.create_ihost(self.context, ihost_dict)

        # verify create happened
        res = self.dbapi.ihost_get_list()
        self.assertEqual(len(res), 1)

    def test_create_ihost_with_values(self):
        ihost_dict = {'mgmt_mac': '00:11:22:33:44:55',
                      'mgmt_ip': '1.2.3.4',
                      'hostname': 'newhost',
                      'invprovision': 'unprovisioned',
                      'personality': 'worker',
                      'administrative': 'locked',
                      'operational': 'disabled',
                      'availability': 'not-installed',
                      'serialid': '1234567890abc',
                      'boot_device': 'sda',
                      'rootfs_device': 'sda',
                      'install_output': 'text',
                      'console': 'ttyS0,115200',
                      'tboot': ''
                      }

        self.service.start()
        res = self.service.create_ihost(self.context, ihost_dict)

        for k, v in ihost_dict.iteritems():
            self.assertEqual(res[k], v)

    def test_update_ihost(self):
        ihost = self._create_test_ihost()

        ihost['mgmt_mac'] = '00:11:22:33:44:55'
        ihost['mgmt_ip'] = '1.2.3.4'
        ihost['hostname'] = 'newhost'
        ihost['invprovision'] = 'unprovisioned'
        ihost['personality'] = 'worker'
        ihost['administrative'] = 'locked'
        ihost['operational'] = 'disabled'
        ihost['availability'] = 'not-installed'
        ihost['serialid'] = '1234567890abc'
        ihost['boot_device'] = 'sda'
        ihost['rootfs_device'] = 'sda'
        ihost['install_output'] = 'text'
        ihost['console'] = 'ttyS0,115200'

        res = self.service.update_ihost(self.context, ihost)

        self.assertEqual(res['mgmt_mac'], '00:11:22:33:44:55')
        self.assertEqual(res['mgmt_ip'], '1.2.3.4')
        self.assertEqual(res['hostname'], 'newhost')
        self.assertEqual(res['invprovision'], 'unprovisioned')
        self.assertEqual(res['personality'], 'worker')
        self.assertEqual(res['administrative'], 'locked')
        self.assertEqual(res['operational'], 'disabled')
        self.assertEqual(res['availability'], 'not-installed')
        self.assertEqual(res['serialid'], '1234567890abc')
        self.assertEqual(res['boot_device'], 'sda')
        self.assertEqual(res['rootfs_device'], 'sda')
        self.assertEqual(res['install_output'], 'text')
        self.assertEqual(res['console'], 'ttyS0,115200')

    def test_update_ihost_id(self):
        ihost = self._create_test_ihost()

        ihost['id'] = '12345'
        self.assertRaises(exception.SysinvException,
                          self.service.update_ihost,
                          self.context,
                          ihost)

    def test_update_ihost_uuid(self):
        ihost = self._create_test_ihost()

        ihost['uuid'] = 'asdf12345'
        self.assertRaises(exception.SysinvException,
                          self.service.update_ihost,
                          self.context,
                          ihost)

    dnsmasq_hosts_file = '/tmp/dnsmasq.hosts'

    def test_configure_ihost_new(self):
        # Test skipped to prevent error message in Jenkins. Error thrown is:
        # in test_configure_ihost_new
        # with open(self.dnsmasq_hosts_file, 'w') as f:
        # IOError: [Errno 13] Permission denied: '/tmp/dnsmasq.hosts'
        self.skipTest("Skipping to prevent failure notification on Jenkins")
        with open(self.dnsmasq_hosts_file, 'w') as f:
            f.write("dhcp-host=08:00:27:0a:fa:fa,worker-1,192.168.204.25,2h\n")

        ihost = self._create_test_ihost()

        ihost['mgmt_mac'] = '00:11:22:33:44:55'
        ihost['mgmt_ip'] = '1.2.3.4'
        ihost['hostname'] = 'newhost'
        ihost['invprovision'] = 'unprovisioned'
        ihost['personality'] = 'worker'
        ihost['administrative'] = 'locked'
        ihost['operational'] = 'disabled'
        ihost['availability'] = 'not-installed'
        ihost['serialid'] = '1234567890abc'
        ihost['boot_device'] = 'sda'
        ihost['rootfs_device'] = 'sda'
        ihost['install_output'] = 'text'
        ihost['console'] = 'ttyS0,115200'

        self.service.configure_ihost(self.context, ihost)

        with open(self.dnsmasq_hosts_file, 'r') as f:
            self.assertEqual(
                f.readline(),
                "dhcp-host=08:00:27:0a:fa:fa,worker-1,192.168.204.25,2h\n")
            self.assertEqual(
                f.readline(),
                "dhcp-host=00:11:22:33:44:55,newhost,1.2.3.4,2h\n")

    def test_configure_ihost_replace(self):
        # Test skipped to prevent error message in Jenkins. Error thrown is:
        # in test_configure_ihost_replace
        # with open(self.dnsmasq_hosts_file, 'w') as f:
        # IOError: [Errno 13] Permission denied: '/tmp/dnsmasq.hosts'
        self.skipTest("Skipping to prevent failure notification on Jenkins")
        with open(self.dnsmasq_hosts_file, 'w') as f:
            f.write("dhcp-host=00:11:22:33:44:55,oldhost,1.2.3.4,2h\n")
            f.write("dhcp-host=08:00:27:0a:fa:fa,worker-1,192.168.204.25,2h\n")

        ihost = self._create_test_ihost()

        ihost['mgmt_mac'] = '00:11:22:33:44:55'
        ihost['mgmt_ip'] = '1.2.3.42'
        ihost['hostname'] = 'newhost'
        ihost['invprovision'] = 'unprovisioned'
        ihost['personality'] = 'worker'
        ihost['administrative'] = 'locked'
        ihost['operational'] = 'disabled'
        ihost['availability'] = 'not-installed'
        ihost['serialid'] = '1234567890abc'
        ihost['boot_device'] = 'sda'
        ihost['rootfs_device'] = 'sda'
        ihost['install_output'] = 'text'
        ihost['console'] = 'ttyS0,115200'

        self.service.configure_ihost(self.context, ihost)

        with open(self.dnsmasq_hosts_file, 'r') as f:
            self.assertEqual(
                f.readline(),
                "dhcp-host=00:11:22:33:44:55,newhost,1.2.3.42,2h\n")
            self.assertEqual(
                f.readline(),
                "dhcp-host=08:00:27:0a:fa:fa,worker-1,192.168.204.25,2h\n")

    def test_configure_ihost_no_hostname(self):
        # Test skipped to prevent error message in Jenkins. Error thrown is:
        # in update_dnsmasq_config
        # os.rename(temp_dnsmasq_hosts_file, dnsmasq_hosts_file)
        # OSError: [Errno 1] Operation not permitted
        self.skipTest("Skipping to prevent failure notification on Jenkins")
        ihost = self._create_test_ihost()

        ihost['hostname'] = ''
        self.assertRaises(exception.SysinvException,
                          self.service.configure_ihost,
                          self.context,
                          ihost)
