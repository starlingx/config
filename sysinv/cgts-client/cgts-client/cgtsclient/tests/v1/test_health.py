#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import testtools

from cgtsclient.v1.health import HealthManager


class FakeAPI(object):
    def __init__(self):
        self.requested_path = None

    def json_request(self, method, path):
        self.requested_path = path
        return None, 'fake health output'


class HealthManagerTest(testtools.TestCase):

    def setUp(self):
        super(HealthManagerTest, self).setUp()
        self.api = FakeAPI()
        self.mgr = HealthManager(self.api)

    def test_get_kube_upgrade_no_arguments(self):
        self.mgr.get_kube_upgrade()
        self.assertEqual(self.api.requested_path, '/v1/health/kube-upgrade')

    def test_get_kube_upgrade_falsy_arguments_are_not_sent(self):
        # This is what a plain 'system health-query-kube-upgrade' sends,
        # and it must keep producing the original request
        self.mgr.get_kube_upgrade({'rootca': False,
                                   'alarm_ignore_list': None,
                                   'use_default_ignore_list': False})
        self.assertEqual(self.api.requested_path, '/v1/health/kube-upgrade')

    def test_get_kube_upgrade_relaxed(self):
        self.mgr.get_kube_upgrade(relaxed=True)
        self.assertEqual(self.api.requested_path,
                         '/v1/health/kube-upgrade/relaxed')

    def test_get_kube_upgrade_rootca(self):
        self.mgr.get_kube_upgrade({'rootca': True})
        self.assertEqual(self.api.requested_path,
                         '/v1/health/kube-upgrade?rootca=True')

    def test_get_kube_upgrade_alarm_ignore_list(self):
        self.mgr.get_kube_upgrade({'alarm_ignore_list': '900.023,900.401'})
        self.assertEqual(
            self.api.requested_path,
            '/v1/health/kube-upgrade?alarm_ignore_list=900.023%2C900.401')

    def test_get_kube_upgrade_use_default_ignore_list(self):
        self.mgr.get_kube_upgrade({'use_default_ignore_list': True})
        self.assertEqual(
            self.api.requested_path,
            '/v1/health/kube-upgrade?use_default_ignore_list=True')

    def test_get_kube_upgrade_all_parameters(self):
        self.mgr.get_kube_upgrade({'rootca': True,
                                   'alarm_ignore_list': '750.005',
                                   'use_default_ignore_list': True},
                                  relaxed=True)
        self.assertEqual(
            self.api.requested_path,
            '/v1/health/kube-upgrade/relaxed?rootca=True'
            '&alarm_ignore_list=750.005&use_default_ignore_list=True')
