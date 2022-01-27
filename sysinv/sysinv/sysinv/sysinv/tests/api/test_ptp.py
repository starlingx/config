# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import uuid

from six.moves import http_client

from sysinv.common import constants
from sysinv.db import api as dbapi
from sysinv.tests.api import base
from sysinv.tests.db import utils as dbutils

HEADER = {'User-Agent': 'sysinv'}


class PTPTestCase(base.FunctionalTest):

    def setUp(self):
        super(PTPTestCase, self).setUp()
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
            administrative=constants.ADMIN_LOCKED
        )
        self.dbapi.ptp_create({})
        self.ptp = self.dbapi.ptp_get_one()
        self.ptp_uuid = self.ptp.uuid

    def _get_path(self, ptp_id=None):
        if ptp_id:
            path = '/ptp/' + ptp_id
        else:
            path = '/ptp'
        return path


class PTPModifyTestCase(PTPTestCase):
    def setUp(self):
        super(PTPModifyTestCase, self).setUp()

    transport_l2 = {'transport': constants.PTP_TRANSPORT_L2}
    transport_udp = {'transport': constants.PTP_TRANSPORT_UDP}

    def modify_ptp(self, input_data):
        response = self.patch_dict('%s' % self._get_path(self.ptp_uuid), input_data)
        self.assertEqual(http_client.OK, response.status_int)
        return response

    def modify_ptp_failure(self, input_data, error_message=None):
        response = self.patch_dict('%s' % self._get_path(self.ptp_uuid), input_data, expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertTrue(response.json['error_message'])
        if error_message:
            self.assertIn(error_message, response.json['error_message'])

    def test_modify_ptp_transport_valid(self):
        # This API is now DEPRECATED:
        message = "Single-instance PTP service API is deprecated"

        # With no ptp hosts we should be able to modify ptp transport
        self.modify_ptp_failure(self.transport_udp, message)
        self.modify_ptp_failure(self.transport_l2, message)

        # If the host is locked we can set the transport to UDP
        self.dbapi.ihost_update(self.worker.id, {'clock_synchronization': constants.PTP})
        self.modify_ptp_failure(self.transport_udp, message)
        self.modify_ptp_failure(self.transport_l2, message)

        # If the host is unlocked it must have a ptp interface with an IP to set to UDP
        self.dbapi.ihost_update(self.worker.id, {'administrative': constants.ADMIN_UNLOCKED})
        interface = {'id': 1,
                     'uuid': str(uuid.uuid4()),
                     'forihostid': self.worker.id,
                     'ifname': 'ptpif',
                     'iftype': constants.INTERFACE_TYPE_ETHERNET,
                     'imac': '02:11:22:33:44:11',
                     'uses': [],
                     'used_by': [],
                     'ifclass': constants.INTERFACE_CLASS_PLATFORM,
                     'ipv4_mode': 'static',
                     'ptp_role': constants.INTERFACE_PTP_ROLE_MASTER
                     }
        dbutils.create_test_interface(**interface)
        address = {'interface_id': '1',
                   'family': 4,
                   'prefix': 24,
                   'address': '192.168.1.2'}
        dbutils.create_test_address(**address)
        self.modify_ptp_failure(self.transport_udp, message)
        self.modify_ptp_failure(self.transport_l2, message)

    def test_modify_ptp_transport_invalid(self):
        # If the host is unlocked it must have a ptp interface with an IP to set to UDP
        self.dbapi.ihost_update(self.worker.id, {'clock_synchronization': constants.PTP})
        self.dbapi.ihost_update(self.worker.id, {'administrative': constants.ADMIN_UNLOCKED})
        interface = {'id': 1,
                     'uuid': str(uuid.uuid4()),
                     'forihostid': self.worker.id,
                     'ifname': 'ptpif',
                     'iftype': constants.INTERFACE_TYPE_ETHERNET,
                     'imac': '02:11:22:33:44:11',
                     'ifclass': constants.INTERFACE_CLASS_PLATFORM,
                     'ptp_role': constants.INTERFACE_PTP_ROLE_MASTER
                     }

        dbutils.create_test_interface(**interface)
        self.modify_ptp_failure(self.transport_udp, "Single-instance PTP service API is deprecated")


class PTPApplyTestCase(PTPTestCase):
    def setUp(self):
        super(PTPApplyTestCase, self).setUp()

    def test_apply_ptp(self):
        # This is basically a null operation for the API but we should test that the function exists
        apply_path = self._get_path() + "/apply"
        # The apply takes no parameters
        response = self.post_json(apply_path, {}, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertTrue(response.json['error_message'])
        self.assertIn("Single-instance PTP service API is deprecated",
                      response.json['error_message'])
