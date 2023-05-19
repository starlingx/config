#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API /kube_upgrade/ methods.
"""

import mock
from six.moves import http_client

from sysinv.common import constants
from sysinv.common import health
from sysinv.common import kubernetes
from sysinv.conductor.manager import ConductorManager

from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils

FAKE_KUBE_VERSIONS = [
    {'version': 'v1.42.1',
     'upgrade_from': [],
     'downgrade_to': [],
     'applied_patches': [],
     'available_patches': [],
     },
    {'version': 'v1.42.2',
     'upgrade_from': ['v1.42.1'],
     'downgrade_to': [],
     'applied_patches': ['KUBE.1', 'KUBE.2'],
     'available_patches': ['KUBE.3'],
     },
    {'version': 'v1.43.1',
     'upgrade_from': ['v1.42.2'],
     'downgrade_to': [],
     'applied_patches': ['KUBE.11', 'KUBE.12'],
     'available_patches': ['KUBE.13'],
     },
    {'version': 'v1.43.2',
     'upgrade_from': ['v1.43.1', 'v1.42.2'],
     'downgrade_to': ['v1.43.1'],
     'applied_patches': ['KUBE.14', 'KUBE.15'],
     'available_patches': ['KUBE.16'],
     },
    {'version': 'v1.43.3',
     'upgrade_from': ['v1.43.2'],
     'downgrade_to': [],
     'applied_patches': [],
     'available_patches': [],
     },
]


class FakeAlarm(object):
    def __init__(self, alarm_id, mgmt_affecting):
        self.alarm_id = alarm_id
        self.mgmt_affecting = mgmt_affecting


FAKE_MGMT_AFFECTING_ALARM = FakeAlarm('900.401', "True")
FAKE_NON_MGMT_AFFECTING_ALARM = FakeAlarm('900.400', "False")


class FakeFmClient(object):
    def __init__(self):
        self.alarm = mock.MagicMock()


class FakeConductorAPI(object):

    def __init__(self):
        self.kube_download_images = mock.MagicMock()
        self.kube_upgrade_networking = mock.MagicMock()
        self.evaluate_apps_reapply = mock.MagicMock()
        self.remove_kube_control_plane_backup = mock.MagicMock()
        self.service = ConductorManager('test-host', 'test-topic')

    def get_system_health(self, context, force=False, upgrade=False,
                          kube_upgrade=False, alarm_ignore_list=None):
        return self.service.get_system_health(
            context,
            force=force,
            upgrade=upgrade,
            kube_upgrade=kube_upgrade,
            alarm_ignore_list=alarm_ignore_list)


class TestKubeUpgrade(base.FunctionalTest):

    def setUp(self):
        super(TestKubeUpgrade, self).setUp()

        # Mock the Conductor API
        self.fake_conductor_api = FakeConductorAPI()
        # rather than start the fake_conductor_api.service, we stage its dbapi
        self.fake_conductor_api.service.dbapi = self.dbapi
        p = mock.patch('sysinv.conductor.rpcapiproxy.ConductorAPI')
        self.mock_conductor_api = p.start()
        self.mock_conductor_api.return_value = self.fake_conductor_api
        self.addCleanup(p.stop)

        # Mock the patching API
        self.mock_patch_is_applied_result = True

        def mock_patch_is_applied(token, timeout, region_name, patches):
            return self.mock_patch_is_applied_result
        self.mocked_patch_is_applied = mock.patch(
            'sysinv.api.controllers.v1.patch_api.patch_is_applied',
            mock_patch_is_applied)
        self.mocked_patch_is_applied.start()
        self.addCleanup(self.mocked_patch_is_applied.stop)

        self.mock_patch_is_available_result = True

        def mock_patch_is_available(token, timeout, region_name, patches):
            return self.mock_patch_is_available_result
        self.mocked_patch_is_available = mock.patch(
            'sysinv.api.controllers.v1.patch_api.patch_is_available',
            mock_patch_is_available)
        self.mocked_patch_is_available.start()
        self.addCleanup(self.mocked_patch_is_available.stop)

        # Mock the KubeVersion
        def mock_get_kube_versions():
            return FAKE_KUBE_VERSIONS
        self.mocked_get_kube_versions = mock.patch(
            'sysinv.common.kubernetes.get_kube_versions',
            mock_get_kube_versions)
        self.mocked_get_kube_versions.start()
        self.addCleanup(self.mocked_get_kube_versions.stop)

        # Mock the KubeOperator
        self.kube_get_node_status_result = None

        def mock_kube_get_node_status(obj):
            return self.kube_get_node_status_result
        self.mocked_kube_get_node_status = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_node_status',
            mock_kube_get_node_status)
        self.mocked_kube_get_node_status.start()
        self.addCleanup(self.mocked_kube_get_node_status.stop)

        # Mock the KubeOperator
        self.kube_get_kubernetes_version_result = 'v1.43.1'

        def mock_kube_get_kubernetes_version(obj):
            return self.kube_get_kubernetes_version_result
        self.mocked_kube_get_kubernetes_version = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_kubernetes_version',
            mock_kube_get_kubernetes_version)
        self.mocked_kube_get_kubernetes_version.start()
        self.addCleanup(self.mocked_kube_get_kubernetes_version.stop)

        self.kube_get_version_states_result = {'v1.42.1': 'available',
                                               'v1.42.2': 'available',
                                               'v1.43.1': 'active',
                                               'v1.43.2': 'available',
                                               'v1.43.3': 'available'}

        def mock_kube_get_version_states(obj):
            return self.kube_get_version_states_result
        self.mocked_kube_get_version_states = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_version_states',
            mock_kube_get_version_states)
        self.mocked_kube_get_version_states.start()
        self.addCleanup(self.mocked_kube_get_version_states.stop)

        # Mock utility function
        self.kube_min_version_result, self.kube_max_version_result = 'v1.42.1', 'v1.43.1'

        def mock_get_app_supported_kube_version(app_name, app_version):
            return self.kube_min_version_result, self.kube_max_version_result
        self.mocked_kube_min_version = mock.patch(
            'sysinv.common.utils.get_app_supported_kube_version',
            mock_get_app_supported_kube_version)
        self.mocked_kube_max_version = mock.patch(
            'sysinv.common.utils.get_app_supported_kube_version',
            mock_get_app_supported_kube_version)
        self.mocked_kube_min_version.start()
        self.mocked_kube_max_version.start()
        self.addCleanup(self.mocked_kube_min_version.stop)
        self.addCleanup(self.mocked_kube_max_version.stop)

        self.setup_health_mocked_calls()

    def setup_health_mocked_calls(self):
        """Mock away the API calls invoked from the health check.

        These calls can be altered by unit tests to test the behaviour
        of systems in different states of health.
        """

        # patch_query_hosts
        p = mock.patch('sysinv.api.controllers.v1.patch_api.patch_query_hosts')
        self.mock_patch_query_hosts = p.start()
        self.mock_patch_query_hosts.return_value = self._patch_current()
        self.addCleanup(p.stop)

        # _check_alarms calls fmclient alarms.list
        self.fake_fm_client = FakeFmClient()
        p = mock.patch('sysinv.common.health.fmclient')
        self.mock_fm_client = p.start()
        self.mock_fm_client.return_value = self.fake_fm_client
        self.addCleanup(p.stop)

        # _check_kube_nodes_ready
        # returns (Success Boolean, List of failed nodes [])
        p = mock.patch.object(health.Health, '_check_kube_nodes_ready')
        self.mock_check_kube_nodes_ready = p.start()
        self.mock_check_kube_nodes_ready.return_value = (True, [])
        self.addCleanup(p.stop)

        # _check_kube_control_plane_pods
        # returns (Success Boolean, List of failed pods [])
        p = mock.patch.object(health.Health, '_check_kube_control_plane_pods')
        self.mock_check_kube_control_plane_pods = p.start()
        self.mock_check_kube_control_plane_pods.return_value = (True, [])
        self.addCleanup(p.stop)

    def _patch_current(self, bool_val=True):
        return {
            'data': [
                {'hostname': 'controller-0',
                 'patch_current': bool_val,
                 },
            ]
        }


class TestListKubeUpgrade(TestKubeUpgrade):

    def test_one(self):
        kube_upgrade = dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
        )
        result = self.get_json('/kube_upgrade/%s' % kube_upgrade['uuid'])

        # Verify that the upgrade has the expected attributes
        self.assertEqual(result['from_version'], 'v1.42.1')
        self.assertEqual(result['to_version'], 'v1.42.2')
        self.assertEqual(result['state'],
                         kubernetes.KUBE_UPGRADING_FIRST_MASTER)

    def test_all(self):
        dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
        )

        # Verify that the upgrade has the expected attributes
        data = self.get_json('/kube_upgrade')
        self.assertEqual(1, len(data['kube_upgrades']))
        self.assertEqual(data['kube_upgrades'][0]['from_version'], 'v1.42.1')
        self.assertEqual(data['kube_upgrades'][0]['to_version'], 'v1.42.2')
        self.assertEqual(data['kube_upgrades'][0]['state'],
                         kubernetes.KUBE_UPGRADING_FIRST_MASTER)


class TestPostKubeUpgradeSimplex(TestKubeUpgrade,
                          dbbase.ProvisionedControllerHostTestCase):
    system_mode = constants.SYSTEM_MODE_SIMPLEX

    @mock.patch('sysinv.common.health.Health._check_trident_compatibility', lambda x: True)
    def test_create_simplex(self):
        # Test creation of upgrade
        self.kube_get_kubernetes_version_result = 'v1.42.1'
        self.kube_get_version_states_result = {'v1.42.1': 'active',
                                               'v1.42.2': 'available',
                                               'v1.43.1': 'available',
                                               'v1.43.2': 'available',
                                               'v1.43.3': 'available'}
        create_dict = dbutils.post_get_test_kube_upgrade(to_version='v1.43.3')
        result = self.post_json('/kube_upgrade', create_dict,
                                headers={'User-Agent': 'sysinv-test'})

        # Verify that the upgrade has the expected attributes
        self.assertEqual(result.json['from_version'], 'v1.42.1')
        self.assertEqual(result.json['to_version'], 'v1.43.3')
        self.assertEqual(result.json['state'],
                         kubernetes.KUBE_UPGRADE_STARTED)

        # see if kubeadm_version was changed in DB
        kube_cmd_version = self.dbapi.kube_cmd_version_get()
        self.assertEqual(kube_cmd_version.kubeadm_version, '1.43.3')

        # Verify that the target version for the host is still the current version
        kube_host_upgrade = self.dbapi.kube_host_upgrade_get_by_host(
            self.host.id)
        self.assertEqual('v1.42.1', kube_host_upgrade.target_version)

    def test_create_simplex_upgrade_path_not_supported(self):
        # Test creation of upgrade when upgrade path is not supported
        self.kube_get_kubernetes_version_result = 'v1.42.1'
        self.kube_get_version_states_result = {'v1.42.1': 'active',
                                               'v1.42.2': 'available',
                                               'v1.43.1': 'unavailable',
                                               'v1.43.2': 'unavailable',
                                               'v1.43.3': 'unavailable'}

        create_dict = dbutils.post_get_test_kube_upgrade(to_version='v1.43.3')
        result = self.post_json('/kube_upgrade', create_dict,
                                headers={'User-Agent': 'sysinv-test'},
                                expect_errors=True)

        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("version v1.43.3 is not in available state",
                      result.json['error_message'])


class TestPostKubeUpgrade(TestKubeUpgrade,
                          dbbase.ProvisionedControllerHostTestCase):

    @mock.patch('sysinv.common.health.Health._check_trident_compatibility', lambda x: True)
    def test_create(self):
        # Test creation of upgrade
        create_dict = dbutils.post_get_test_kube_upgrade(to_version='v1.43.2')
        result = self.post_json('/kube_upgrade', create_dict,
                                headers={'User-Agent': 'sysinv-test'})

        # Verify that the upgrade has the expected attributes
        self.assertEqual(result.json['from_version'], 'v1.43.1')
        self.assertEqual(result.json['to_version'], 'v1.43.2')
        self.assertEqual(result.json['state'],
                         kubernetes.KUBE_UPGRADE_STARTED)

        # see if kubeadm_version was changed in DB
        kube_cmd_version = self.dbapi.kube_cmd_version_get()
        self.assertEqual(kube_cmd_version.kubeadm_version, '1.43.2')

        # Verify that the target version for the host was updated
        kube_host_upgrade = self.dbapi.kube_host_upgrade_get_by_host(
            self.host.id)
        self.assertEqual('v1.43.1', kube_host_upgrade.target_version)

    def test_create_platform_upgrade_exists(self):
        # Test creation of upgrade when platform upgrade in progress
        dbutils.create_test_load(software_version=dbutils.SW_VERSION_NEW,
                                 compatible_version=dbutils.SW_VERSION,
                                 state=constants.IMPORTED_LOAD_STATE)
        dbutils.create_test_upgrade()

        create_dict = dbutils.post_get_test_kube_upgrade(to_version='v1.43.2')
        result = self.post_json('/kube_upgrade', create_dict,
                                headers={'User-Agent': 'sysinv-test'},
                                expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("upgrade cannot be done while a platform upgrade",
                      result.json['error_message'])

    def test_create_upgrade_exists(self):
        # Test creation of upgrade when upgrade already exists
        dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
        )
        create_dict = dbutils.post_get_test_kube_upgrade(to_version='v1.43.2')
        result = self.post_json('/kube_upgrade', create_dict,
                                headers={'User-Agent': 'sysinv-test'},
                                expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("upgrade is already in progress",
                      result.json['error_message'])

    def test_create_target_version_does_not_exist(self):
        # Test creation of upgrade when target version doesn't exist
        create_dict = dbutils.post_get_test_kube_upgrade(to_version='v1.45.45')
        result = self.post_json('/kube_upgrade', create_dict,
                                headers={'User-Agent': 'sysinv-test'},
                                expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("version v1.45.45 is not available",
                      result.json['error_message'])

    def test_create_upgrade_path_not_supported(self):
        # Test creation of upgrade when upgrade path is not supported
        create_dict = dbutils.post_get_test_kube_upgrade(to_version='v1.43.3')
        result = self.post_json('/kube_upgrade', create_dict,
                                headers={'User-Agent': 'sysinv-test'},
                                expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("version v1.43.1 cannot upgrade to",
                      result.json['error_message'])

    def test_create_current_version_not_active(self):
        # Test creation of upgrade when current version is not active
        self.kube_get_version_states_result = {'v1.42.1': 'available',
                                               'v1.42.2': 'available',
                                               'v1.43.1': 'partial',
                                               'v1.43.2': 'available',
                                               'v1.43.3': 'available'}
        create_dict = dbutils.post_get_test_kube_upgrade(to_version='v1.43.2')
        result = self.post_json('/kube_upgrade', create_dict,
                                headers={'User-Agent': 'sysinv-test'},
                                expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("version v1.43.1 is not active",
                      result.json['error_message'])

    def test_create_installed_app_not_compatible(self):
        # Test creation of upgrade when the installed application isn't
        # compatible with the new kubernetes version

        # Create application
        dbutils.create_test_app(
            name='stx-openstack',
            app_version='1.0-19',
            manifest_name='manifest',
            manifest_file='stx-openstack.yaml',
            status='applied',
            active=True)

        create_dict = dbutils.post_get_test_kube_upgrade(to_version='v1.43.2')
        result = self.post_json('/kube_upgrade', create_dict,
                                headers={'User-Agent': 'sysinv-test'},
                                expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("incompatible with the new Kubernetes version v1.43.2",
                      result.json['error_message'])

    @mock.patch('sysinv.common.health.Health._check_trident_compatibility', lambda x: True)
    def test_create_system_unhealthy_from_alarms(self):
        """Test creation of a kube upgrade while there are alarms"""
        # Test creation of upgrade when system health check fails
        # 1 alarm, when force is not specified will return False
        self.fake_fm_client.alarm.list.return_value = \
            [FAKE_NON_MGMT_AFFECTING_ALARM, ]

        create_dict = dbutils.post_get_test_kube_upgrade(to_version='v1.43.2')
        result = self.post_json('/kube_upgrade', create_dict,
                                headers={'User-Agent': 'sysinv-test'},
                                expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("System is not in a valid state",
                      result.json['error_message'])

    @mock.patch('sysinv.common.health.Health._check_trident_compatibility', lambda x: True)
    def test_force_create_system_unhealthy_from_alarms(self):
        # Test creation of upgrade when system health check fails but
        # overridden with force

        # mock a 'non' mgmt_affecting alarm, upgrade can be forced
        self.fake_fm_client.alarm.list.return_value = \
            [FAKE_NON_MGMT_AFFECTING_ALARM, ]
        create_dict = dbutils.post_get_test_kube_upgrade(
            to_version='v1.43.2')
        create_dict['force'] = True
        result = self.post_json('/kube_upgrade', create_dict,
                                headers={'User-Agent': 'sysinv-test'})

        # Verify that the upgrade has the expected attributes
        self.assertEqual(result.json['from_version'], 'v1.43.1')
        self.assertEqual(result.json['to_version'], 'v1.43.2')
        self.assertEqual(result.json['state'],
                         kubernetes.KUBE_UPGRADE_STARTED)

    @mock.patch('sysinv.common.health.Health._check_trident_compatibility', lambda x: True)
    def test_force_create_system_unhealthy_from_mgmt_affecting_alarms(self):
        """ Test kube upgrade create fails when mgmt affecting alarms found"""

        # mock a mgmt_affecting alarm, upgrade cannot be forced
        self.fake_fm_client.alarm.list.return_value = \
            [FAKE_MGMT_AFFECTING_ALARM, ]
        create_dict = dbutils.post_get_test_kube_upgrade(
            to_version='v1.43.2')
        create_dict['force'] = True
        result = self.post_json('/kube_upgrade', create_dict,
                                headers={'User-Agent': 'sysinv-test'},
                                expect_errors=True)

        # Verify that the upgrade has the expected attributes
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("System is not in a valid state",
                      result.json['error_message'])

    @mock.patch('sysinv.common.health.Health._check_trident_compatibility', lambda x: True)
    def test_create_system_can_ignore_alarms(self):
        # Test creation of upgrade when system health check fails but
        # overridden with force

        # mock a 'non' mgmt_affecting alarm, upgrade can be forced
        self.fake_fm_client.alarm.list.return_value = \
            [FAKE_MGMT_AFFECTING_ALARM, ]
        create_dict = dbutils.post_get_test_kube_upgrade(
            to_version='v1.43.2')
        # ignore the alarm_id for the mgmt affecting alarm
        create_dict['alarm_ignore_list'] = "['900.401',]"
        result = self.post_json('/kube_upgrade', create_dict,
                                headers={'User-Agent': 'sysinv-test'})

        # Verify that the upgrade has the expected attributes
        self.assertEqual(result.json['from_version'], 'v1.43.1')
        self.assertEqual(result.json['to_version'], 'v1.43.2')
        self.assertEqual(result.json['state'],
                         kubernetes.KUBE_UPGRADE_STARTED)

    @mock.patch('sysinv.common.health.Health._check_trident_compatibility', lambda x: True)
    def test_create_system_unhealthy_from_bad_apps(self):
        """ Test kube upgrade create fails when invalid kube app found"""

        # The app is not fully setup, health query should fail
        dbutils.create_test_app(name='broken-app',
                                status=constants.APP_APPLY_IN_PROGRESS)

        # Test creation of upgrade when system health check fails from bad app
        create_dict = dbutils.post_get_test_kube_upgrade(
            to_version='v1.43.2')
        create_dict['force'] = True
        result = self.post_json('/kube_upgrade', create_dict,
                                headers={'User-Agent': 'sysinv-test'},
                                expect_errors=True)

        # Verify that the upgrade has the expected attributes
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        # The error should contain the following:
        #   System is not in a valid state for kubernetes upgrade.
        #   Run system health-query-kube-upgrade for more details.
        self.assertIn("Run system health-query-kube-upgrade for more details.",
                      result.json['error_message'])

    @mock.patch('sysinv.common.health.Health._check_trident_compatibility', lambda x: True)
    def test_create_no_patches_required(self):
        # Test creation of upgrade when no applied patches are required
        self.mock_patch_is_applied_result = False
        self.mock_patch_is_available_result = False
        self.kube_get_kubernetes_version_result = 'v1.43.2'
        self.kube_get_version_states_result = {'v1.42.1': 'available',
                                               'v1.42.2': 'available',
                                               'v1.43.1': 'available',
                                               'v1.43.2': 'active',
                                               'v1.43.3': 'available'}
        create_dict = dbutils.post_get_test_kube_upgrade(to_version='v1.43.3')
        result = self.post_json('/kube_upgrade', create_dict,
                                headers={'User-Agent': 'sysinv-test'})

        # Verify that the upgrade has the expected attributes
        self.assertEqual(result.json['from_version'], 'v1.43.2')
        self.assertEqual(result.json['to_version'], 'v1.43.3')
        self.assertEqual(result.json['state'],
                         kubernetes.KUBE_UPGRADE_STARTED)

    def test_create_applied_patch_missing(self):
        # Test creation of upgrade when applied patch is missing
        self.mock_patch_is_applied_result = False
        create_dict = dbutils.post_get_test_kube_upgrade(to_version='v1.43.2')
        result = self.post_json('/kube_upgrade', create_dict,
                                headers={'User-Agent': 'sysinv-test'},
                                expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("The following patches must be applied",
                      result.json['error_message'])

    def test_create_available_patch_missing(self):
        # Test creation of upgrade when available patch is missing
        self.mock_patch_is_available_result = False
        create_dict = dbutils.post_get_test_kube_upgrade(to_version='v1.43.2')
        result = self.post_json('/kube_upgrade', create_dict,
                                headers={'User-Agent': 'sysinv-test'},
                                expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("The following patches must be available",
                      result.json['error_message'])


class TestPatch(TestKubeUpgrade,
                dbbase.ProvisionedControllerHostTestCase):

    def test_update_state_download_images(self):
        # Test updating the state of an upgrade to download images

        # Create the upgrade
        kube_upgrade = dbutils.create_test_kube_upgrade(
            from_version='v1.43.1',
            to_version='v1.43.2',
            state=kubernetes.KUBE_UPGRADE_STARTED)
        uuid = kube_upgrade.uuid

        # Update state
        new_state = kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES
        response = self.patch_json('/kube_upgrade',
                                   [{'path': '/state',
                                     'value': new_state,
                                     'op': 'replace'}],
                                   headers={'User-Agent': 'sysinv-test'})
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json['from_version'], 'v1.43.1')
        self.assertEqual(response.json['to_version'], 'v1.43.2')
        self.assertEqual(response.json['state'], new_state)

        # Verify that the images were downloaded
        self.fake_conductor_api.kube_download_images.\
            assert_called_with(mock.ANY, 'v1.43.2')

        # Verify that the upgrade was updated with the new state
        result = self.get_json('/kube_upgrade/%s' % uuid)
        self.assertEqual(result['from_version'], 'v1.43.1')
        self.assertEqual(result['to_version'], 'v1.43.2')
        self.assertEqual(result['state'], new_state)

    def test_update_state_download_images_after_failure(self):
        # Test updating the state of an upgrade to download images after a
        # failure

        # Create the upgrade
        kube_upgrade = dbutils.create_test_kube_upgrade(
            from_version='v1.43.1',
            to_version='v1.43.2',
            state=kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES_FAILED)
        uuid = kube_upgrade.uuid

        # Update state
        new_state = kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES
        response = self.patch_json('/kube_upgrade',
                                   [{'path': '/state',
                                     'value': new_state,
                                     'op': 'replace'}],
                                   headers={'User-Agent': 'sysinv-test'})
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json['from_version'], 'v1.43.1')
        self.assertEqual(response.json['to_version'], 'v1.43.2')
        self.assertEqual(response.json['state'], new_state)

        # Verify that the images were downloaded
        self.fake_conductor_api.kube_download_images.\
            assert_called_with(mock.ANY, 'v1.43.2')

        # Verify that the upgrade was updated with the new state
        result = self.get_json('/kube_upgrade/%s' % uuid)
        self.assertEqual(result['from_version'], 'v1.43.1')
        self.assertEqual(result['to_version'], 'v1.43.2')
        self.assertEqual(result['state'], new_state)

    def test_update_state_download_images_invalid_state(self):
        # Test updating the state of an upgrade to download images in an
        # invalid state

        # Create the upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.43.1',
            to_version='v1.43.2',
            state=kubernetes.KUBE_UPGRADING_KUBELETS)

        # Update state
        new_state = kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES
        result = self.patch_json('/kube_upgrade',
                                 [{'path': '/state',
                                   'value': new_state,
                                   'op': 'replace'}],
                                 headers={'User-Agent': 'sysinv-test'},
                                 expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("Kubernetes upgrade must be in",
                      result.json['error_message'])

    def test_update_state_upgrade_networking(self):
        # Test updating the state of an upgrade to upgrade networking

        # Create the upgrade
        kube_upgrade = dbutils.create_test_kube_upgrade(
            from_version='v1.43.1',
            to_version='v1.43.2',
            state=kubernetes.KUBE_UPGRADE_DOWNLOADED_IMAGES)
        uuid = kube_upgrade.uuid

        # Update state
        new_state = kubernetes.KUBE_UPGRADING_NETWORKING
        response = self.patch_json('/kube_upgrade',
                                   [{'path': '/state',
                                     'value': new_state,
                                     'op': 'replace'}],
                                   headers={'User-Agent': 'sysinv-test'})
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json['from_version'], 'v1.43.1')
        self.assertEqual(response.json['to_version'], 'v1.43.2')
        self.assertEqual(response.json['state'], new_state)

        # Verify that networking was upgraded
        self.fake_conductor_api.kube_upgrade_networking.\
            assert_called_with(mock.ANY, 'v1.43.2')

        # Verify that the upgrade was updated with the new state
        result = self.get_json('/kube_upgrade/%s' % uuid)
        self.assertEqual(result['from_version'], 'v1.43.1')
        self.assertEqual(result['to_version'], 'v1.43.2')
        self.assertEqual(result['state'], new_state)

    def test_update_state_upgrade_networking_after_failure(self):
        # Test updating the state of an upgrade to upgrade networking after a
        # failure

        # Create the upgrade
        kube_upgrade = dbutils.create_test_kube_upgrade(
            from_version='v1.43.1',
            to_version='v1.43.2',
            state=kubernetes.KUBE_UPGRADING_NETWORKING_FAILED)
        uuid = kube_upgrade.uuid

        # Update state
        new_state = kubernetes.KUBE_UPGRADING_NETWORKING
        response = self.patch_json('/kube_upgrade',
                                   [{'path': '/state',
                                     'value': new_state,
                                     'op': 'replace'}],
                                   headers={'User-Agent': 'sysinv-test'})
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json['from_version'], 'v1.43.1')
        self.assertEqual(response.json['to_version'], 'v1.43.2')
        self.assertEqual(response.json['state'], new_state)

        # Verify that networking was upgraded
        self.fake_conductor_api.kube_upgrade_networking.\
            assert_called_with(mock.ANY, 'v1.43.2')

        # Verify that the upgrade was updated with the new state
        result = self.get_json('/kube_upgrade/%s' % uuid)
        self.assertEqual(result['from_version'], 'v1.43.1')
        self.assertEqual(result['to_version'], 'v1.43.2')
        self.assertEqual(result['state'], new_state)

    def test_update_state_upgrade_networking_invalid_state(self):
        # Test updating the state of an upgrade to upgrade networking in an
        # invalid state

        # Create the upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.43.1',
            to_version='v1.43.2',
            state=kubernetes.KUBE_UPGRADING_KUBELETS)

        # Update state
        new_state = kubernetes.KUBE_UPGRADING_NETWORKING
        result = self.patch_json('/kube_upgrade',
                                 [{'path': '/state',
                                   'value': new_state,
                                   'op': 'replace'}],
                                 headers={'User-Agent': 'sysinv-test'},
                                 expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("Kubernetes upgrade must be in",
                      result.json['error_message'])

    def test_update_state_complete(self):
        # Test updating the state of an upgrade to complete
        self.kube_get_version_states_result = {'v1.42.1': 'available',
                                               'v1.42.2': 'available',
                                               'v1.43.1': 'available',
                                               'v1.43.2': 'active',
                                               'v1.43.3': 'available'}

        # Create the upgrade
        kube_upgrade = dbutils.create_test_kube_upgrade(
            from_version='v1.43.1',
            to_version='v1.43.2',
            state=kubernetes.KUBE_UPGRADING_KUBELETS)
        uuid = kube_upgrade.uuid

        # Mark the kube host upgrade as upgraded-kubelet
        values = {
            'status': kubernetes.KUBE_HOST_UPGRADED_KUBELET
        }
        self.dbapi.kube_host_upgrade_update(1, values)

        # Update state
        new_state = kubernetes.KUBE_UPGRADE_COMPLETE
        response = self.patch_json('/kube_upgrade',
                                   [{'path': '/state',
                                     'value': new_state,
                                     'op': 'replace'}],
                                   headers={'User-Agent': 'sysinv-test'})

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json['from_version'], 'v1.43.1')
        self.assertEqual(response.json['to_version'], 'v1.43.2')
        self.assertEqual(response.json['state'], new_state)

        # see if kubelet_version was changed in DB
        kube_cmd_version = self.dbapi.kube_cmd_version_get()
        self.assertEqual(kube_cmd_version.kubelet_version, '1.43.2')

        # Verify that the upgrade was updated with the new state
        result = self.get_json('/kube_upgrade/%s' % uuid)
        self.assertEqual(result['from_version'], 'v1.43.1')
        self.assertEqual(result['to_version'], 'v1.43.2')
        self.assertEqual(result['state'], new_state)

        # Verify that apps reapply evaluation was triggered
        self.fake_conductor_api.evaluate_apps_reapply.assert_called_once()

    def test_update_state_complete_incomplete_host(self):
        # Test updating the state of an upgrade to complete when a host has
        # not completed its upgrade
        self.kube_get_version_states_result = {'v1.42.1': 'available',
                                               'v1.42.2': 'available',
                                               'v1.43.1': 'available',
                                               'v1.43.2': 'active',
                                               'v1.43.3': 'available'}

        # Create the upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.43.1',
            to_version='v1.43.2',
            state=kubernetes.KUBE_UPGRADING_KUBELETS)

        # Mark the kube host upgrade as failed
        values = {
            'status': kubernetes.KUBE_HOST_UPGRADING_CONTROL_PLANE_FAILED
        }
        self.dbapi.kube_host_upgrade_update(1, values)

        # Update state
        new_state = kubernetes.KUBE_UPGRADE_COMPLETE
        result = self.patch_json('/kube_upgrade',
                                 [{'path': '/state',
                                   'value': new_state,
                                   'op': 'replace'}],
                                 headers={'User-Agent': 'sysinv-test'},
                                 expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("At least one host has not completed",
                      result.json['error_message'])

    def test_update_state_no_upgrade(self):
        # Test updating the state when an upgrade doesn't exist

        # Update state
        new_state = kubernetes.KUBE_UPGRADING_NETWORKING
        result = self.patch_json('/kube_upgrade',
                                 [{'path': '/state',
                                   'value': new_state,
                                   'op': 'replace'}],
                                 headers={'User-Agent': 'sysinv-test'},
                                 expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("kubernetes upgrade is not in progress",
                      result.json['error_message'])

    def test_update_state_bad_state(self):
        # Test updating the state of an upgrade with a bad state

        # Create the upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.43.1',
            to_version='v1.43.2',
            state=kubernetes.KUBE_UPGRADED_FIRST_MASTER)

        # Update state
        new_state = 'this-is-a-bad-state'
        result = self.patch_json('/kube_upgrade',
                                 [{'path': '/state',
                                   'value': new_state,
                                   'op': 'replace'}],
                                 headers={'User-Agent': 'sysinv-test'},
                                 expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("Invalid state",
                      result.json['error_message'])

    def test_update_failed_state(self):
        # Test updating the state of an upgrade with a failed state

        # Create the upgrade
        kube_upgrade = dbutils.create_test_kube_upgrade(
            from_version='v1.43.1',
            to_version='v1.43.2',
            state=kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES)
        uuid = kube_upgrade.uuid

        # Update state
        new_state = kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES_FAILED
        result = self.patch_json('/kube_upgrade',
                                 [{'path': '/state',
                                   'value': new_state,
                                   'op': 'replace'}],
                                 headers={'User-Agent': 'sysinv-test'},
                                 expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(result.status_code, http_client.OK)
        self.assertEqual(result.json['state'], new_state)

        # see if state was changed in DB
        kube_cmd_version = self.dbapi.kube_upgrade_get_one()
        self.assertEqual(kube_cmd_version.state, new_state)

        # Verify that the upgrade was updated with the new state
        result = self.get_json('/kube_upgrade/%s' % uuid)
        self.assertEqual(result['from_version'], 'v1.43.1')
        self.assertEqual(result['to_version'], 'v1.43.2')
        self.assertEqual(result['state'], new_state)

    def test_update_state_failed_invalid_state(self):
        # Test updating the invalid state of an upgrade with a failed state

        # Create the upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.43.1',
            to_version='v1.43.2',
            state=kubernetes.KUBE_UPGRADE_DOWNLOADED_IMAGES)

        # Update state
        new_state = kubernetes.KUBE_UPGRADE_DOWNLOADING_IMAGES_FAILED
        result = self.patch_json('/kube_upgrade',
                                 [{'path': '/state',
                                   'value': new_state,
                                   'op': 'replace'}],
                                 headers={'User-Agent': 'sysinv-test'},
                                 expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(result.status_code, http_client.BAD_REQUEST)
        self.assertIn(("A kubernetes upgrade is in downloaded-images state "
                       "cannot be set to failed"),
                      result.json['error_message'])


class TestDelete(TestKubeUpgrade):

    def test_delete(self):
        # Test deleting an upgrade

        # Create the upgrade
        kube_upgrade = dbutils.create_test_kube_upgrade(
            from_version='v1.43.1',
            to_version='v1.43.2',
            state=kubernetes.KUBE_UPGRADE_COMPLETE)

        # Delete the upgrade
        self.delete('/kube_upgrade',
                    headers={'User-Agent': 'sysinv-test'})

        # Verify the upgrade no longer exists
        response = self.get_json('/kube_upgrade/%s' % kube_upgrade.uuid,
                                 expect_errors=True)
        self.assertEqual(response.status_int, 404)
        self.assertEqual(response.content_type, 'application/json')
        self.assertTrue(response.json['error_message'])
        self.fake_conductor_api.\
            remove_kube_control_plane_backup.assert_called()

    def test_delete_upgrade_not_complete(self):
        # Test deleting an upgrade when upgrade is not complete

        # Create the upgrade
        dbutils.create_test_kube_upgrade(
            from_version='v1.43.1',
            to_version='v1.43.2',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER)

        # Delete the upgrade
        result = self.delete('/kube_upgrade',
                             headers={'User-Agent': 'sysinv-test'},
                             expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("upgrade must be in upgrade-complete",
                      result.json['error_message'])
        self.fake_conductor_api.\
            remove_kube_control_plane_backup.assert_not_called()

    def test_delete_no_upgrade(self):
        # Test deleting an upgrade when no upgrade exists

        # Delete the upgrade
        result = self.delete('/kube_upgrade',
                             headers={'User-Agent': 'sysinv-test'},
                             expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("upgrade is not in progress",
                      result.json['error_message'])
        self.fake_conductor_api.\
            remove_kube_control_plane_backup.assert_not_called()
