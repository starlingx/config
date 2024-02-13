#
# Copyright (c) 2022-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Test class for Sysinv Keystone notification listener.
"""

import mock

from sysinv.conductor import keystone_listener
from sysinv.common import utils
from sysinv.common import constants
from sysinv.tests.db import base
from sysinv.db import api as dbapi


class KeystoneListenerTestCase(base.BaseSystemTestCase):

    def test_get_transport_url(self):

        db_api = dbapi.get_instance()
        network_object = utils.get_primary_address_by_name(db_api,
                    utils.format_address_name(constants.CONTROLLER_HOSTNAME,
                                              constants.NETWORK_TYPE_MGMT),
                    constants.NETWORK_TYPE_MGMT).address

        class keyring_obj(object):
            @staticmethod
            def get_password(param1, param2):
                return 'passwrd'

        with mock.patch("sysinv.conductor.keystone_listener.keyring", keyring_obj):
            self.assertEqual(
                keystone_listener.get_transport_url(),
                f"rabbit://guest:passwrd@{network_object}:5672"
            )
