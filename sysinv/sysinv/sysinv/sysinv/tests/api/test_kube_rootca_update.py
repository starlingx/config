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

# API_HEADERS are a generic header passed to most API calls
API_HEADERS = {'User-Agent': 'sysinv-test'}


class FakeFmClient(object):
    def __init__(self):
        self.alarm = mock.MagicMock()


class FakeConductorAPI(object):

    def __init__(self):
        self.service = ConductorManager('test-host', 'test-topic')
        self.save_kubernetes_rootca_cert = self.fake_config_certificate
        self.generate_kubernetes_rootca_cert = self.fake_generate_rootca
        self.config_certificate_return = None
        self.platcert_k8s_secret_value = False
        self.generate_rootca_return = None

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

    def fake_generate_rootca(self, context):
        return self.generate_rootca_return

    def setup_config_certificate(self, data):
        self.config_certificate_return = data

    def setup_generate_rootca(self, data):
        self.generate_rootca_return = data

    def kube_certificate_update_by_host(self, context, host, phase):
        return

    def kube_certificate_update_for_pods(self, context, phase):
        return


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
        self.headers = API_HEADERS
        self.addCleanup(p.stop)

        self.setup_health_mocked_calls()
        self.setup_kubernetes_calls()

    def setup_kubernetes_calls(self):
        """ Mock KubeOperator calls invoked from methods in kube rootca update """

        # mocking kube_create_secret
        p = mock.patch('sysinv.common.kubernetes.KubeOperator.kube_create_secret')
        self.mock_kube_create_secret = p.start()
        self.addCleanup(p.stop)

        # mocking apply_custom_resource
        l = mock.patch('sysinv.common.kubernetes.KubeOperator.apply_custom_resource')
        self.mock_conductor_api = l.start()
        self.addCleanup(l.stop)

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


class TestPostKubeRootCAUpdate(TestKubeRootCAUpdate,
                        dbbase.ProvisionedControllerHostTestCase):

    def test_create(self):
        # Test creation of kubernetes rootca update
        create_dict = dbutils.get_test_kube_rootca_update()
        result = self.post_json('/kube_rootca_update', create_dict,
                                headers=self.headers)

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
                                headers=self.headers,
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
                                headers=self.headers,
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
                                headers=self.headers,
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
                                headers=self.headers,
                                expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("rootca update cannot be done while a platform upgrade",
                      result.json['error_message'])


class TestKubeRootCAUpdateShow(TestKubeRootCAUpdate,
                        dbbase.ProvisionedControllerHostTestCase):

    def setUp(self):
        super(TestKubeRootCAUpdateShow, self).setUp()
        self.url = '/kube_rootca_update'

    def test_update_show_update_exists(self):
        dbutils.create_test_kube_rootca_update()

        result = self.get_json(self.url)
        updates = result['kube_rootca_updates']

        self.assertEqual(updates[0]['state'], kubernetes.KUBE_ROOTCA_UPDATE_STARTED)

    def test_update_show_no_update_exists(self):
        result = self.get_json(self.url)
        updates = result['kube_rootca_updates']
        self.assertEqual(len(updates), 0)


class TestKubeRootCAHostUpdateList(TestKubeRootCAUpdate,
                        dbbase.ProvisionedAIODuplexSystemTestCase):

    def setUp(self):
        super(TestKubeRootCAHostUpdateList, self).setUp()
        self.url = '/kube_rootca_update/hosts'

    def test_update_list_update_exists(self):
        """ Test that output lists the hosts"""
        dbutils.create_test_kube_rootca_update(state=kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS)

        dbutils.create_test_kube_rootca_host_update(host_id=self.host.id,
            state=kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTBOTHCAS)
        dbutils.create_test_kube_rootca_host_update(host_id=self.host2.id,
            state=kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTBOTHCAS)

        result = self.get_json(self.url)
        updates = result['kube_host_updates']

        self.assertEqual(updates[0]['state'], kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTBOTHCAS)
        self.assertEqual(updates[1]['state'], kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTBOTHCAS)
        self.assertEqual(updates[0]['personality'], constants.CONTROLLER)
        self.assertEqual(updates[1]['personality'], constants.CONTROLLER)
        self.assertEqual(updates[0]['hostname'], 'controller-0')
        self.assertEqual(updates[1]['hostname'], 'controller-1')
        self.assertEqual(updates[0]['target_rootca_cert'], 'newCertSerial')
        self.assertEqual(updates[1]['target_rootca_cert'], 'newCertSerial')
        self.assertEqual(updates[0]['effective_rootca_cert'], 'oldCertSerial')
        self.assertEqual(updates[1]['effective_rootca_cert'], 'oldCertSerial')

    def test_update_list_with_no_update_in_progress(self):
        """ Should return error message if no update has been stared"""

        result = self.get_json(self.url, expect_errors=True)

        self.assertEqual(result.status_int, http_client.BAD_REQUEST)
        self.assertIn("kube-rootca-update-list rejected: No kubernetes root CA update in progress.",
                        result.json['error_message'])

    def test_update_list_with_no_host_update_in_progress(self):
        """ Should return warning message if no update has been stared on hosts"""
        dbutils.create_test_kube_rootca_update(state=kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS)

        result = self.get_json(self.url)
        updates = result['kube_host_updates']
        self.assertEqual(len(updates), 0)


class TestKubeRootCAUpload(TestKubeRootCAUpdate,
                        dbbase.ProvisionedControllerHostTestCase):

    def setUp(self):
        super(TestKubeRootCAUpload, self).setUp()
        self.fake_conductor_api.service.dbapi = self.dbapi

    def test_upload_rootca(self):
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
                                  headers=self.headers,
                                  expect_errors=False)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        resp = json.loads(response.body)

        self.assertTrue(resp.get('success'))
        self.assertEqual(resp.get('success'), fake_save_rootca_return.get('success'))
        self.assertFalse(resp.get('error'))


class TestKubeRootCAGenerate(TestKubeRootCAUpdate,
                        dbbase.ProvisionedControllerHostTestCase):
    def setUp(self):
        super(TestKubeRootCAGenerate, self).setUp()
        self.fake_conductor_api.service.dbapi = self.dbapi

    def test_generate_rootca(self):
        dbutils.create_test_kube_rootca_update(state=kubernetes.KUBE_ROOTCA_UPDATE_STARTED)
        fake_save_rootca_return = {'success': '137813-123', 'error': ''}

        self.fake_conductor_api.\
            setup_generate_rootca(fake_save_rootca_return)

        response = self.post_json('/kube_rootca_update/generate_cert', {},
                                headers=self.headers,
                                expect_errors=True)

        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        resp = json.loads(response.body)

        self.assertTrue(resp.get('success'))
        self.assertEqual(resp.get('success'), fake_save_rootca_return.get('success'))
        self.assertFalse(resp.get('error'))


class TestKubeRootCAPodsUpdateTrustBothCAs(TestKubeRootCAUpdate,
                        dbbase.ProvisionedControllerHostTestCase):
    def setUp(self):
        super(TestKubeRootCAPodsUpdateTrustBothCAs, self).setUp()
        self.phase = constants.KUBE_CERT_UPDATE_TRUSTBOTHCAS
        self.post_url = '/kube_rootca_update/pods'
        self.headers = API_HEADERS

    def test_rootca_update_pods(self):
        # Test kube root CA update for pods
        create_dict = {'phase': self.phase}

        dbutils.create_test_kube_rootca_update(
            state=kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTBOTHCAS)

        result = self.post_json(self.post_url, create_dict,
                                headers=self.headers)

        # Verify that the rootca update pods has the expected attributes
        self.assertEqual(result.json['state'],
                        kubernetes.KUBE_ROOTCA_UPDATING_PODS_TRUSTBOTHCAS)

    def test_rootca_update_pods_reject_wrong_state(self):
        # Test kube root CA update for pods - rejected, not in right state
        create_dict = {'phase': self.phase}

        # The cluster update state is in updating hosts
        dbutils.create_test_kube_rootca_update(
            state=kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS)

        result = self.post_json(self.post_url, create_dict,
                                headers=self.headers,
                                expect_errors=True)

        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("kube-rootca-pods-update phase trust-both-cas rejected: "
                "not allowed when cluster update is in state: %s. "
                "(only allowed when in state: %s or %s)"
                % (kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS,
                kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTBOTHCAS,
                kubernetes.KUBE_ROOTCA_UPDATING_PODS_TRUSTBOTHCAS_FAILED),
                result.json['error_message'])


class TestKubeRootCAPodsUpdateTrustNewCA(TestKubeRootCAUpdate,
                        dbbase.ProvisionedControllerHostTestCase):
    def setUp(self):
        super(TestKubeRootCAPodsUpdateTrustNewCA, self).setUp()
        self.phase = constants.KUBE_CERT_UPDATE_TRUSTNEWCA
        self.post_url = '/kube_rootca_update/pods'
        self.headers = API_HEADERS

    def test_rootca_update_pods(self):
        # Test kube root CA update for pods
        create_dict = {'phase': self.phase}

        dbutils.create_test_kube_rootca_update(
            state=kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTNEWCA)

        result = self.post_json(self.post_url, create_dict,
                                headers=self.headers)

        # Verify that the rootca update pods has the expected attributes
        self.assertEqual(result.json['state'],
                        kubernetes.KUBE_ROOTCA_UPDATING_PODS_TRUSTNEWCA)

    def test_rootca_update_pods_reject_wrong_state(self):
        # Test kube root CA update for pods - rejected, not in right state
        create_dict = {'phase': self.phase}

        # The cluster update state is in updating hosts
        dbutils.create_test_kube_rootca_update(
            state=kubernetes.KUBE_ROOTCA_UPDATING_PODS_TRUSTBOTHCAS)

        result = self.post_json(self.post_url, create_dict,
                                headers=self.headers,
                                expect_errors=True)

        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("kube-rootca-pods-update phase trust-new-ca rejected: "
                "not allowed when cluster update is in state: %s. "
                "(only allowed when in state: %s or %s)"
                % (kubernetes.KUBE_ROOTCA_UPDATING_PODS_TRUSTBOTHCAS,
                kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTNEWCA,
                kubernetes.KUBE_ROOTCA_UPDATING_PODS_TRUSTNEWCA_FAILED),
                result.json['error_message'])


class TestKubeRootCAHostUpdate(base.FunctionalTest):
    # API_PREFIX is the prefix for the URL
    API_PREFIX = '/ihosts'

    def setUp(self):
        super(TestKubeRootCAHostUpdate, self).setUp()

        # Mock the Conductor API
        self.fake_conductor_api = FakeConductorAPI()
        # rather than start the fake_conductor_api.service, we stage its dbapi
        self.fake_conductor_api.service.dbapi = self.dbapi
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI')
        self.mock_conductor_api = p.start()
        self.mock_conductor_api.return_value = self.fake_conductor_api
        self.addCleanup(p.stop)

        # Mock kubeOperator kube_get_secret
        mock_kube_get_secret = mock.MagicMock()
        z = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_secret',
            mock_kube_get_secret
        )
        self.mock_kube_get_secret = z.start()
        self.addCleanup(z.stop)

        self.headers = API_HEADERS
        self.post_url = \
            '%s/%s/kube_update_ca' % (self.API_PREFIX, self.host.uuid)

    def set_phase(self, phase):
        self.phase = phase


class TestKubeRootCAHostUpdateTrustBothCAs(TestKubeRootCAHostUpdate,
                        dbbase.ProvisionedAIODuplexSystemTestCase):
    def setUp(self):
        super(TestKubeRootCAHostUpdateTrustBothCAs, self).setUp()
        # Set host root CA update phase
        self.set_phase(constants.KUBE_CERT_UPDATE_TRUSTBOTHCAS)

    def test_create_from_uploaded_cert(self):
        # Test creation of kubernetes rootca host update
        create_dict = {'phase': self.phase}

        dbutils.create_test_kube_rootca_update(
            state=kubernetes.KUBE_ROOTCA_UPDATE_CERT_UPLOADED)

        result = self.post_json(self.post_url, create_dict,
                                headers=self.headers)
        # Verify that the rootca host update has the expected attributes
        self.assertEqual(result.json['state'],
                        kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS)

        # Verify that the overall rootca update has the expected attributes
        result = dbutils.get_kube_rootca_update()
        self.assertEqual(result.state,
                        kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS)

    def test_create_from_generated_cert(self):
        # Test creation of kubernetes rootca host update
        create_dict = {'phase': self.phase}

        dbutils.create_test_kube_rootca_update(
            state=kubernetes.KUBE_ROOTCA_UPDATE_CERT_GENERATED)

        result = self.post_json(self.post_url, create_dict,
                                headers=self.headers)
        # Verify that the rootca host update has the expected attributes
        self.assertEqual(result.json['state'],
                        kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS)

        # Verify that the overall rootca update has the expected attributes
        result = dbutils.get_kube_rootca_update()
        self.assertEqual(result.state,
                        kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS)

    def test_create_other_hosts_updated(self):
        # Test creation of kubernetes rootca host update
        # Allow update on this hosts when overall update in progress
        create_dict = {'phase': self.phase}

        # overall update in progress with some hosts updated
        dbutils.create_test_kube_rootca_update(
            state=kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS)

        # root CA update on host2 completed
        dbutils.create_test_kube_rootca_host_update(host_id=self.host2.id,
            state=kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTBOTHCAS)

        result = self.post_json(self.post_url, create_dict,
                                headers=self.headers)
        # Verify that the rootca host update has the expected attributes
        self.assertEqual(result.json['state'],
                        kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS)

        # Verify that the overall rootca update has the expected attributes
        result = dbutils.get_kube_rootca_update()
        self.assertEqual(result.state,
                        kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS)

    def test_create_failed_retry(self):
        # Test creation of kubernetes rootca host update
        # Allow retry update if update on this host ever failed
        create_dict = {'phase': self.phase}

        # overall update in progress with some hosts updated
        dbutils.create_test_kube_rootca_update(
            state=kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS_FAILED)

        # root CA update on host ever failed
        dbutils.create_test_kube_rootca_host_update(host_id=self.host.id,
            state=kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS_FAILED)

        result = self.post_json(self.post_url, create_dict,
                                headers=self.headers)
        # Verify that the rootca host update has the expected attributes
        self.assertEqual(result.json['state'],
                        kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS)

        # Verify that the overall rootca update has the expected attributes
        result = dbutils.get_kube_rootca_update()
        self.assertEqual(result.state,
                        kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS)

    def test_create_failed_update_not_started(self):
        # Test creation failed since update not started yet
        create_dict = {'phase': self.phase}

        result = self.post_json(self.post_url, create_dict,
                                headers=self.headers,
                                expect_errors=True)

        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("kube-rootca-host-update rejected: "
                    "No update in progress", result.json['error_message'])

    def test_create_failed_no_cert_available(self):
        # Test creation failed since no new cert uploaded or generated
        create_dict = {'phase': self.phase}

        dbutils.create_test_kube_rootca_update(
            state=kubernetes.KUBE_ROOTCA_UPDATE_STARTED)

        result = self.post_json(self.post_url, create_dict,
                                headers=self.headers,
                                expect_errors=True)

        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("kube-rootca-host-update rejected: No new certificate "
                    "available", result.json['error_message'])

    def test_create_failed_host_update_completed(self):
        # Test creation failed since this host already updated
        create_dict = {'phase': self.phase}

        # Overall update is in progress
        dbutils.create_test_kube_rootca_update(
            state=kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS)

        # This host has been updated
        dbutils.create_test_kube_rootca_host_update(host_id=self.host.id,
            state=kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTBOTHCAS)

        result = self.post_json(self.post_url, create_dict,
                                headers=self.headers,
                                expect_errors=True)

        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("kube-rootca-host-update rejected: update already "
                    "completed on host %s" % self.host.hostname,
                    result.json['error_message'])

    def test_create_failed_hosts_update_in_progress(self):
        # Test creation failed since there is update in progess on a host
        create_dict = {'phase': self.phase}

        # overall update in progress with some hosts updated
        dbutils.create_test_kube_rootca_update(
            state=kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS)

        # root CA update on host2 is in progress
        dbutils.create_test_kube_rootca_host_update(host_id=self.host2.id,
            state=kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS)

        result = self.post_json(self.post_url, create_dict,
                                headers=self.headers,
                                expect_errors=True)

        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("kube-rootca-host-update rejected: update in progress "
                    "on host %s" % self.host2.hostname,
                    result.json['error_message'])

    def test_create_failed_hosts_update_failed(self):
        # Test creation failed since there is host update failed on a host
        create_dict = {'phase': self.phase}

        # overall update in progress with some hosts updated
        dbutils.create_test_kube_rootca_update(
            state=kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS_FAILED)

        # root CA update on host2 failed
        dbutils.create_test_kube_rootca_host_update(host_id=self.host2.id,
            state=kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS_FAILED)

        result = self.post_json(self.post_url, create_dict,
                                headers=self.headers,
                                expect_errors=True)

        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("kube-rootca-host-update rejected: not allowed when "
                    "cluster update is in state: %s"
                    % kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS_FAILED,
                    result.json['error_message'])

    def test_create_failed_not_in_correct_state_updatecerts_failed(self):
        # Test creation failed when user tries this phase after the overall
        # update already passes this phase.
        create_dict = {'phase': self.phase}

        # overall update is in updateCerts phase
        dbutils.create_test_kube_rootca_update(
            state=kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS_FAILED)

        # root CA update phase updateCerts on host failed
        dbutils.create_test_kube_rootca_host_update(host_id=self.host.id,
            state=kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS_FAILED)

        result = self.post_json(self.post_url, create_dict,
                                headers=self.headers,
                                expect_errors=True)

        # but client make a call to perform update phase trust-both-cas
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("kube-rootca-host-update rejected: not allowed when "
                    "cluster update is in state: %s"
                    % kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS_FAILED,
                    result.json['error_message'])

    def test_create_failed_not_in_correct_state_updatecerts_in_progress(self):
        # Test creation failed when user tries this phase after the overall
        # update already passes this phase.
        create_dict = {'phase': self.phase}

        # overall update is in updateCerts phase
        dbutils.create_test_kube_rootca_update(
            state=kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS)

        # root CA update phase updateCerts completed on this host
        dbutils.create_test_kube_rootca_host_update(host_id=self.host.id,
            state=kubernetes.KUBE_ROOTCA_UPDATED_HOST_UPDATECERTS)

        # but client make a call to perform update phase trust-both-cas
        result = self.post_json(self.post_url, create_dict,
                                headers=self.headers,
                                expect_errors=True)

        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("kube-rootca-host-update rejected: not allowed when "
                    "cluster update is in state: %s"
                    % kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS,
                    result.json['error_message'])


class TestKubeRootCAHostUpdateUpdateCerts(TestKubeRootCAHostUpdate,
                        dbbase.ProvisionedAIODuplexSystemTestCase):
    def setUp(self):
        super(TestKubeRootCAHostUpdateUpdateCerts, self).setUp()
        # Set host root CA update phase
        self.set_phase(constants.KUBE_CERT_UPDATE_UPDATECERTS)

    def test_updatecerts_host_update(self):
        create_dict = {'phase': self.phase}

        # overall update is in updateCerts phase
        dbutils.create_test_kube_rootca_update(
            state=kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS)

        # root CA update phase updateCerts completed on this host
        dbutils.create_test_kube_rootca_host_update(host_id=self.host.id,
            state=kubernetes.KUBE_ROOTCA_UPDATED_PODS_TRUSTNEWCA)

        result = self.post_json(self.post_url, create_dict,
                                headers=self.headers,
                                expect_errors=True)

        self.assertEqual(result.json['state'], kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS)
        self.assertEqual(result.json['effective_rootca_cert'], 'oldCertSerial')
        self.assertEqual(result.json['target_rootca_cert'], 'newCertSerial')

    def test_updatecerts_host_update_inprogress(self):
        create_dict = {'phase': self.phase}

        # overall update is in updateCerts phase
        dbutils.create_test_kube_rootca_update(
            state=kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS)

        # root CA update phase updateCerts completed on this host
        dbutils.create_test_kube_rootca_host_update(host_id=self.host.id,
            state=kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS)

        result = self.post_json(self.post_url, create_dict,
                                headers=self.headers,
                                expect_errors=True)

        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("kube-rootca-host-update rejected: update in progress", result.json['error_message'])

    def test_updatecerts_host_update_failed_cluster_in_advanced_state(self):
        create_dict = {'phase': self.phase}

        # overall update is in updated_trustnewca phase
        dbutils.create_test_kube_rootca_update(
            state=kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTNEWCA)

        dbutils.create_test_kube_rootca_host_update(host_id=self.host.id,
            state=kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTNEWCA)

        result = self.post_json(self.post_url, create_dict,
                                headers=self.headers,
                                expect_errors=True)

        # but client make a call to perform update phase updatecerts
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("kube-rootca-host-update rejected: not "
                        "allowed when cluster update is in state: %s. "
                        "(only allowed when in state: %s)"
                        % (kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTNEWCA,
                        kubernetes.KUBE_ROOTCA_UPDATED_PODS_TRUSTBOTHCAS),
            result.json['error_message'])

    def test_updatecerts_host_update_failed_already_completed(self):
        create_dict = {'phase': self.phase}

        # overall update is in updated_trustnewca phase
        dbutils.create_test_kube_rootca_update(
            state=kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS)

        dbutils.create_test_kube_rootca_host_update(host_id=self.host.id,
            state=kubernetes.KUBE_ROOTCA_UPDATED_HOST_UPDATECERTS)

        result = self.post_json(self.post_url, create_dict,
                                headers=self.headers,
                                expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("kube-rootca-host-update rejected: update already "
                        "completed on host %s" % self.host.hostname, result.json['error_message'])

    def test_updatecerts_host_update_in_past_state(self):
        create_dict = {'phase': self.phase}

        # overall update is in updated_trustnewca phase
        dbutils.create_test_kube_rootca_update(
            state=kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS)

        dbutils.create_test_kube_rootca_host_update(host_id=self.host.id,
            state=kubernetes.KUBE_ROOTCA_UPDATED_HOST_TRUSTBOTHCAS)

        result = self.post_json(self.post_url, create_dict,
                                headers=self.headers,
                                expect_errors=True)

        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("kube-rootca-host-update rejected: not "
                        "allowed when cluster update is in state: %s. "
                        "(only allowed when in state: %s)"
                        % (kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS,
                        kubernetes.KUBE_ROOTCA_UPDATED_PODS_TRUSTBOTHCAS),
            result.json['error_message'])

    def test_updatecerts_host_update_failed_host(self):
        create_dict = {'phase': self.phase}

        # overall update is in updated_trustnewca phase
        dbutils.create_test_kube_rootca_update(
            state=kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS_FAILED)

        dbutils.create_test_kube_rootca_host_update(host_id=self.host2.id,
            state=kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS_FAILED)

        dbutils.create_test_kube_rootca_host_update(host_id=self.host.id,
            state=kubernetes.KUBE_ROOTCA_UPDATED_PODS_TRUSTBOTHCAS)

        result = self.post_json(self.post_url, create_dict,
                                headers=self.headers,
                                expect_errors=True)

        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("kube-rootca-host-update rejected: update failed "
                            "on host %s" % self.host2.hostname,
                            result.json['error_message'])
