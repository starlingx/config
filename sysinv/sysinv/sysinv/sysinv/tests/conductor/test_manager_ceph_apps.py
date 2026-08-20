#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Additional coverage tests for ConductorManager."""

import mock

from sysinv.common import constants
from sysinv.conductor import manager

from sysinv.db import api as dbapi
from sysinv.tests.db import base


class ConductorManagerCoverageTest(base.BaseHostTestCase):
    """Tests targeting uncovered conductor/manager.py functions."""

    def setUp(self):
        super(ConductorManagerCoverageTest, self).setUp()
        self.service = manager.ConductorManager(
            'test-host',
            'test-topic'
        )
        self.service.dbapi = dbapi.get_instance()
        self.service._puppet = mock.MagicMock()
        self.service._ceph = mock.MagicMock()
        self.service._kube = mock.MagicMock()
        self.service._kube_operator = mock.MagicMock()
        self.service._usm = mock.MagicMock()
        self.service._mtc_address = 'localhost'
        self.service._mtc_port = 2112
        self.service._api_token = None
        self.context = self.admin_context

    # --- _check_ceph_backend_state ---

    # --- evaluate_apps_reapply ---

    # --- _lookup_static_ip_address ---
    def test_lookup_static_ip_address_not_found(self):
        result = self.service._lookup_static_ip_address(
            'nonexistent-host', constants.NETWORK_TYPE_MGMT)
        self.assertIsNone(result)

    # --- iplatform_update_by_ihost ---

    # --- _create_default_service_parameter ---

    # --- _find_local_interface_name ---

    # --- _find_local_mgmt_interface_vlan_id ---
