#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Test class for Sysinv Keystone notification listener.
"""

import mock

from sysinv.conductor import keystone_listener
from sysinv.tests.db import base


class KeystoneListenerTestCase(base.DbTestCase):

    def test_get_transport_url(self):

        class db_api_test(object):
            @staticmethod
            def get_instance():
                return get_db()

        class get_db(object):
            def address_get_by_name(self, param1):
                return get_network_ob()

        class get_network_ob(object):
            address = '192.168.101.1'

        class keyring_obj(object):
            @staticmethod
            def get_password(param1, param2):
                return 'passwrd'

        with mock.patch("sysinv.conductor.keystone_listener.dbapi", db_api_test):
            with mock.patch("sysinv.conductor.keystone_listener.keyring", keyring_obj):
                self.assertEqual(
                    keystone_listener.get_transport_url(),
                    "rabbit://guest:passwrd@192.168.101.1:5672"
                )
