# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from sysinv.helm import helm
from sysinv.tests import keyring_fixture


class HelmTestCaseMixin(object):

    def setUp(self):
        super(HelmTestCaseMixin, self).setUp()
        self.operator = helm.HelmOperator(self.dbapi)
        self.useFixture(keyring_fixture.KeyringBackend())
        mock.patch('sysinv.common.utils.is_virtual',
                   return_value=False).start()
