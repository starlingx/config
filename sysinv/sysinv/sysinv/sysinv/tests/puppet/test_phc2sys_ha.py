# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Tests the HA phc2sys read-only socket option derived by
# NetworkingPuppet._set_ptp_instance_global_parameters().
#
import mock
import uuid as uuidutils

from sysinv.common import constants
from sysinv.puppet import networking as networking_puppet
from sysinv.tests import base as test_base

RO_OPTION = 'ha_phc2sys_com_ro_socket'
DEFAULT_RO = constants.PTP_PHC2SYS_HA_SOCKET_PATH + 'ro'


class TestPhc2sysHaReadOnlySocket(test_base.TestCase):

    def setUp(self):
        super(TestPhc2sysHaReadOnlySocket, self).setUp()
        self.operator = networking_puppet.NetworkingPuppet(mock.MagicMock())

    def _run(self, service, pairs, name='inst1'):
        inst = {'id': 1, 'uuid': str(uuidutils.uuid4()), 'name': name,
                'service': service}
        params = [{'name': n, 'value': v, 'section': 'global',
                   'owners': [inst['uuid']]} for n, v in pairs]
        out = self.operator._set_ptp_instance_global_parameters(
            [inst], params)
        return out[name]['global_parameters']

    def test_default_injection_for_ha_instance(self):
        gp = self._run('phc2sys', [('ha_enabled', '1')])
        self.assertEqual(gp[RO_OPTION], DEFAULT_RO)

    def test_injection_derived_from_user_socket_any_order(self):
        for pairs in ([('ha_enabled', '1'),
                       ('ha_phc2sys_com_socket', '/var/run/custom')],
                      [('ha_phc2sys_com_socket', '/var/run/custom'),
                       ('ha_enabled', '1')]):
            gp = self._run('phc2sys', pairs)
            self.assertEqual(gp[RO_OPTION], '/var/run/customro')

    def test_no_injection_when_ha_disabled_or_unset(self):
        self.assertNotIn(RO_OPTION,
                         self._run('phc2sys', [('ha_enabled', '0')]))
        self.assertNotIn(RO_OPTION, self._run('phc2sys', []))

    def test_no_injection_for_non_phc2sys(self):
        gp = self._run('ptp4l', [('ha_enabled', '1')])
        self.assertNotIn(RO_OPTION, gp)

    def test_derived_value_wins_over_user_value(self):
        gp = self._run('phc2sys',
                       [(RO_OPTION, '/user/value'), ('ha_enabled', '1')])
        self.assertEqual(gp[RO_OPTION], DEFAULT_RO)
