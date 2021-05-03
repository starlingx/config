"""
Tests for the API /kube_rootca_update/ methods.
"""

import json
import mock
import os
from six.moves import http_client
from sysinv.common import constants
from sysinv.common import health
from sysinv.common import kubernetes
from sysinv.conductor.manager import ConductorManager

from sysinv.tests.api import base
from sysinv.tests.db import utils as dbutils
from sysinv.tests.db import base as dbbase


class FakeAlarm(object):
    def __init__(self, alarm_id, mgmt_affecting):
        self.alarm_id = alarm_id
        self.mgmt_affecting = mgmt_affecting


FAKE_MGMT_ALARM = FakeAlarm('900.401', "True")
# FAKE_NON_MGMT_AFFECTING_ALARM = FakeAlarm('900.400', "False")


class FakeFmClient(object):
    def __init__(self):
        self.alarm = mock.MagicMock()


class FakeConductorAPI(object):

    def __init__(self):
        self.service = ConductorManager('test-host', 'test-topic')
        self.save_kubernetes_rootca_cert = self.fake_config_certificate
        self.config_certificate_return = None
        self.platcert_k8s_secret_value = False

    def get_system_health(self, context, force=False, upgrade=False,
                          kube_upgrade=False, kube_rootca_update=False,
                          alarm_ignore_list=None):
        return self.service.get_system_health(
            context,
            force=force,
            upgrade=upgrade,
            kube_upgrade=kube_upgrade,
            kube_rootca_update=kube_rootca_update,
            alarm_ignore_list=alarm_ignore_list)

    def fake_config_certificate(self, context, pem):
        return self.config_certificate_return

    def setup_config_certificate(self, data):
        self.config_certificate_return = data


class TestKubeRootCAUpdate(base.FunctionalTest):

    def setUp(self):
        super(TestKubeRootCAUpdate, self).setUp()

        # Mock the Conductor API
        self.fake_conductor_api = FakeConductorAPI()
        # rather than start the fake_conductor_api.service, we stage its dbapi
        self.fake_conductor_api.service.dbapi = self.dbapi
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI')
        self.mock_conductor_api = p.start()
        self.mock_conductor_api.return_value = self.fake_conductor_api
        self.addCleanup(p.stop)

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


class TestPostKubeRootUpdate(TestKubeRootCAUpdate,
                        dbbase.ProvisionedControllerHostTestCase):

    def test_create(self):
        # Test creation of kubernetes rootca update
        create_dict = dbutils.get_test_kube_rootca_update()
        result = self.post_json('/kube_rootca_update', create_dict,
                                headers={'User-Agent': 'sysinv-test'})

        # Verify that the kubernetes rootca update has the expected attributes
        self.assertEqual(result.json['state'],
                        kubernetes.KUBE_ROOTCA_UPDATE_STARTED)
        self.assertNotEqual(result.json['from_rootca_cert'], None)
        self.assertEqual(result.json['from_rootca_cert'], 'oldCertSerial')

    def test_create_rootca_update_unhealthy_from_alarms(self):
        """ Test creation of kube rootca update while there are alarms"""
        # Test creation of kubernetes rootca update when system health check fails
        # 1 alarm will return False
        self.fake_fm_client.alarm.list.return_value = \
            [FAKE_MGMT_ALARM, ]

        # Test creation of kubernetes rootca update
        create_dict = dbutils.get_test_kube_rootca_update()
        result = self.post_json('/kube_rootca_update', create_dict,
                                headers={'User-Agent': 'sysinv-test'},
                                expect_errors=True)

        # Verify that the rootca update has the expected attributes
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        # The error should contain the following:
        #   System is not in a valid state for kubernetes rootca update.
        #   Run system health-query-kube-rootca-update for more details.
        self.assertIn("System is not in a valid state",
                      result.json['error_message'])

    def test_create_rootca_update_exists(self):
        # Test creation of rootca update when a kubernetes rootca update already exists
        dbutils.create_test_kube_rootca_update()
        create_dict = dbutils.post_get_test_kube_rootca_update(state=kubernetes.KUBE_ROOTCA_UPDATE_STARTED)
        result = self.post_json('/kube_rootca_update', create_dict,
                                headers={'User-Agent': 'sysinv-test'},
                                expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("A kubernetes rootca update is already in progress",
                      result.json['error_message'])

    def test_create_kube_upgrade_exists(self):
        # Test creation of rootca update when kubernetes upgrade in progress
        dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
        )
        create_dict = dbutils.post_get_test_kube_rootca_update()
        result = self.post_json('/kube_rootca_update', create_dict,
                                headers={'User-Agent': 'sysinv-test'},
                                expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("rootca update cannot be done while a kube upgrade "
                "is in progress",
                      result.json['error_message'])

    def test_create_platform_upgrade_exists(self):
        # Test creation of rootca update when platform upgrade in progress
        dbutils.create_test_load(software_version=dbutils.SW_VERSION_NEW,
                                 compatible_version=dbutils.SW_VERSION,
                                 state=constants.IMPORTED_LOAD_STATE)
        dbutils.create_test_upgrade()

        create_dict = dbutils.post_get_test_kube_rootca_update()
        result = self.post_json('/kube_rootca_update', create_dict,
                                headers={'User-Agent': 'sysinv-test'},
                                expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("rootca update cannot be done while a platform upgrade",
                      result.json['error_message'])


class TestKubeRootCAUpload(TestKubeRootCAUpdate,
                        dbbase.ProvisionedControllerHostTestCase):

    def setUp(self):
        super(TestKubeRootCAUpload, self).setUp()
        self.fake_conductor_api.service.dbapi = self.dbapi

    @mock.patch.object(kubernetes.KubeOperator,
                       'kube_create_secret')
    @mock.patch.object(kubernetes.KubeOperator,
                       'apply_custom_resource')
    def test_upload_rootca(self, mock_create_secret, mock_create_custom_resource):
        dbutils.create_test_kube_rootca_update(state=kubernetes.KUBE_ROOTCA_UPDATE_STARTED)
        certfile = os.path.join(os.path.dirname(__file__), "data",
                                'rootca-with-key.pem')

        fake_save_rootca_return = {'success': '137813-123', 'error': ''}

        self.fake_conductor_api.\
            setup_config_certificate(fake_save_rootca_return)

        files = [('file', certfile)]
        response = self.post_with_files('%s/%s' % ('/kube_rootca_update', 'upload'),
                                  {},
                                  upload_files=files,
                                  headers={'User-Agent': 'sysinv-test'},
                                  expect_errors=False)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        resp = json.loads(response.body)

        self.assertTrue(resp.get('success'))
        self.assertEqual(resp.get('success'), fake_save_rootca_return.get('success'))
        self.assertFalse(resp.get('error'))
