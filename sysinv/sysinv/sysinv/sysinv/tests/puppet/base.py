# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from sysinv.puppet import puppet
from sysinv.tests import keyring_fixture


class PuppetTestCaseMixin(object):

    def setUp(self):
        super(PuppetTestCaseMixin, self).setUp()
        self.operator = puppet.PuppetOperator(self.dbapi)
        self.useFixture(keyring_fixture.KeyringBackend())
        self.mock_write_config = mock.patch.object(puppet.PuppetOperator, '_write_config').start()
        mock.patch('sysinv.common.utils.is_virtual', return_value=False).start()
        mock.patch('sysinv.puppet.kubernetes.KubernetesPuppet._get_host_join_command',
                   return_value={}).start()

    def assertConfigParameters(self, mock_write_config, parameters):
        """Validate the configuration contains the supplied parameters"""
        config = mock_write_config.call_args[0][1]  # single call, second param
        for key, value in parameters.items():
            self.assertIn(key, config)
            self.assertEqual(config.get(key), value)
