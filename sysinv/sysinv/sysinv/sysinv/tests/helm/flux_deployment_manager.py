# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Unit tests for FluxDeploymentManager."""

import mock
import subprocess

from sysinv.helm import flux
from sysinv.tests import base as test_base


FAKE_CONF = {
    'flux_helm_controller_image': 'registry.local:9001/ghcr.io/fluxcd/helm-controller',
    'flux_helm_controller_tag': 'v0.37.0',
    'flux_source_controller_image': 'registry.local:9001/ghcr.io/fluxcd/source-controller',
    'flux_source_controller_tag': 'v1.2.0',
    'flux_kustomize_controller_image': 'registry.local:9001/ghcr.io/fluxcd/kustomize-controller',
    'flux_kustomize_controller_tag': 'v1.2.0',
    'flux_notification_controller_image': 'registry.local:9001/ghcr.io/fluxcd/notification-controller',
    'flux_notification_controller_tag': 'v1.2.0',
    'enable_kustomize_controller': True,
    'enable_notification_controller': True,
    'fluxcd_namespace': 'flux-helm',
    'fluxcd_secret_name': 'flux-registry-secret',
    'flux_helm_release_name': 'flux2',
    'local_registry': 'registry.local:9001',
}


FAKE_HISTORY = [
    {"chart": "flux2-2.12.0", "revision": 1, "status": "superseded"},
    {"chart": "flux2-2.15.0", "revision": 2, "status": "superseded"},
    {"chart": "flux2-2.18.0", "revision": 3, "status": "deployed"},
]


class TestFluxDeploymentManagerBase(test_base.TestCase):
    """Base class for FluxDeploymentManager tests."""

    @mock.patch('builtins.open', mock.mock_open(read_data=''))
    @mock.patch('yaml.safe_load', return_value=FAKE_CONF)
    def setUp(self, mock_yaml_load):
        super(TestFluxDeploymentManagerBase, self).setUp()
        self.mock_dbapi = mock.MagicMock()
        self.manager = flux.FluxDeploymentManager(self.mock_dbapi)
        self.manager.conf_dict = FAKE_CONF.copy()


class TestGetImageList(TestFluxDeploymentManagerBase):
    """Tests for FluxDeploymentManager.get_image_list()."""

    def test_all_controllers_enabled(self):
        """All four images returned when all controllers are enabled."""
        images = self.manager.get_image_list()
        self.assertEqual(len(images), 4)
        self.assertIn(
            f"{FAKE_CONF['flux_helm_controller_image']}:{FAKE_CONF['flux_helm_controller_tag']}",
            images)
        self.assertIn(
            f"{FAKE_CONF['flux_source_controller_image']}:{FAKE_CONF['flux_source_controller_tag']}",
            images)
        self.assertIn(
            f"{FAKE_CONF['flux_kustomize_controller_image']}:"
            f"{FAKE_CONF['flux_kustomize_controller_tag']}",
            images)
        self.assertIn(
            f"{FAKE_CONF['flux_notification_controller_image']}:"
            f"{FAKE_CONF['flux_notification_controller_tag']}",
            images)

    def test_kustomize_disabled(self):
        """Kustomize image excluded when disabled."""
        self.manager.conf_dict['enable_kustomize_controller'] = False
        images = self.manager.get_image_list()
        self.assertEqual(len(images), 3)
        self.assertNotIn(
            f"{FAKE_CONF['flux_kustomize_controller_image']}:"
            f"{FAKE_CONF['flux_kustomize_controller_tag']}",
            images)

    def test_notification_disabled(self):
        """Notification image excluded when disabled."""
        self.manager.conf_dict['enable_notification_controller'] = False
        images = self.manager.get_image_list()
        self.assertEqual(len(images), 3)
        self.assertNotIn(
            f"{FAKE_CONF['flux_notification_controller_image']}:"
            f"{FAKE_CONF['flux_notification_controller_tag']}",
            images)

    def test_both_optional_disabled(self):
        """Only helm and source images when both optional controllers disabled."""
        self.manager.conf_dict['enable_kustomize_controller'] = False
        self.manager.conf_dict['enable_notification_controller'] = False
        images = self.manager.get_image_list()
        self.assertEqual(len(images), 2)


class TestDownloadImages(TestFluxDeploymentManagerBase):
    """Tests for FluxDeploymentManager.download_images()."""

    @mock.patch.object(flux.ContainerImageDownloader,
                       'download_images_from_upstream_to_local_reg_and_crictl',
                       return_value=True)
    def test_download_success(self, mock_download):
        """Returns True when all images download successfully."""
        result = self.manager.download_images()
        self.assertTrue(result)
        mock_download.assert_called_once()

    @mock.patch.object(flux.ContainerImageDownloader,
                       'download_images_from_upstream_to_local_reg_and_crictl',
                       return_value=False)
    def test_download_failure(self, mock_download):
        """Returns False when image download fails."""
        result = self.manager.download_images()
        self.assertFalse(result)


class TestGetChartPath(TestFluxDeploymentManagerBase):
    """Tests for FluxDeploymentManager.get_chart_path()."""

    @mock.patch('glob.glob', return_value=['/charts/flux2-2.18.0.tgz'])
    def test_single_chart_found(self, mock_glob):
        """Returns chart path when exactly one chart is found."""
        result = flux.FluxDeploymentManager.get_chart_path('/charts')
        self.assertEqual(result, '/charts/flux2-2.18.0.tgz')

    @mock.patch('glob.glob', return_value=[])
    def test_no_chart_found(self, mock_glob):
        """Returns None when no chart is found."""
        result = flux.FluxDeploymentManager.get_chart_path('/charts')
        self.assertIsNone(result)

    @mock.patch('glob.glob', return_value=[
        '/charts/flux2-2.15.0.tgz', '/charts/flux2-2.18.0.tgz'])
    def test_multiple_charts_found(self, mock_glob):
        """Returns None when multiple charts are found."""
        result = flux.FluxDeploymentManager.get_chart_path('/charts')
        self.assertIsNone(result)


class TestDeleteCrd(TestFluxDeploymentManagerBase):
    """Tests for FluxDeploymentManager.delete_crd()."""

    @mock.patch('sysinv.common.kubernetes.KubeOperator')
    def test_delete_crd_success(self, mock_kube_cls):
        """Returns True on successful CRD deletion."""
        mock_kube = mock_kube_cls.return_value
        result = self.manager.delete_crd('test.crd.io')
        self.assertTrue(result)
        mock_kube.delete_custom_resource_definition.assert_called_once_with('test.crd.io')

    @mock.patch('sysinv.common.kubernetes.KubeOperator')
    def test_delete_crd_failure(self, mock_kube_cls):
        """Returns False when CRD deletion raises an exception."""
        mock_kube = mock_kube_cls.return_value
        mock_kube.delete_custom_resource_definition.side_effect = Exception("Not found")
        result = self.manager.delete_crd('test.crd.io')
        self.assertFalse(result)

    @mock.patch('sysinv.common.kubernetes.KubeOperator')
    def test_delete_oci_repository_crd(self, mock_kube_cls):
        """delete_oci_repository_crd deletes the correct CRD name."""
        mock_kube = mock_kube_cls.return_value
        self.manager.delete_oci_repository_crd()
        mock_kube.delete_custom_resource_definition.assert_called_once_with(
            flux.OCI_REPO_CRD)


class TestIsTargetVersionInstalled(TestFluxDeploymentManagerBase):
    """Tests for FluxDeploymentManager.is_target_version_installed()."""

    def test_target_version_deployed(self):
        """Returns True when the latest entry matches target version."""
        history = [
            {"chart": "flux2-2.15.0", "revision": 1, "status": "superseded"},
            {"chart": "flux2-2.18.0", "revision": 2, "status": "deployed"},
        ]
        result = flux.FluxDeploymentManager.is_target_version_installed(
            history, "2.18.0")
        self.assertTrue(result)

    def test_target_version_not_deployed(self):
        """Returns False when the latest entry does not match."""
        history = [
            {"chart": "flux2-2.15.0", "revision": 1, "status": "superseded"},
            {"chart": "flux2-2.18.0", "revision": 2, "status": "deployed"},
        ]
        result = flux.FluxDeploymentManager.is_target_version_installed(
            history, "2.15.0")
        self.assertFalse(result)

    def test_target_version_not_in_deployed_state(self):
        """Returns False when the latest entry matches but is not deployed."""
        history = [
            {"chart": "flux2-2.18.0", "revision": 1, "status": "failed"},
        ]
        result = flux.FluxDeploymentManager.is_target_version_installed(
            history, "2.18.0")
        self.assertFalse(result)

    def test_empty_history_raises(self):
        """Raises ValueError when history is empty."""
        self.assertRaises(
            ValueError,
            flux.FluxDeploymentManager.is_target_version_installed,
            [], "2.18.0")


class TestGetTargetRevision(TestFluxDeploymentManagerBase):
    """Tests for FluxDeploymentManager.get_target_revision()."""

    def test_finds_revision_in_history(self):
        """Returns the correct revision number for the target version."""
        result = flux.FluxDeploymentManager.get_target_revision(
            FAKE_HISTORY, "2.15.0")
        self.assertEqual(result, 2)

    def test_finds_oldest_matching_revision(self):
        """Returns the most recent matching revision (reversed search)."""
        history = [
            {"chart": "flux2-2.15.0", "revision": 1, "status": "superseded"},
            {"chart": "flux2-2.15.0", "revision": 2, "status": "superseded"},
            {"chart": "flux2-2.18.0", "revision": 3, "status": "deployed"},
        ]
        result = flux.FluxDeploymentManager.get_target_revision(
            history, "2.15.0")
        self.assertEqual(result, 2)

    def test_version_not_in_history(self):
        """Returns None when the target version is not in history."""
        result = flux.FluxDeploymentManager.get_target_revision(
            FAKE_HISTORY, "2.10.0")
        self.assertIsNone(result)


class TestUpgradeControllers(TestFluxDeploymentManagerBase):
    """Tests for FluxDeploymentManager.upgrade_controllers()."""

    @mock.patch('subprocess.run')
    @mock.patch.object(flux.FluxDeploymentManager, 'generate_overrides',
                       return_value='overrides_content')
    @mock.patch.object(flux.FluxDeploymentManager, 'download_images',
                       return_value=True)
    @mock.patch.object(flux.FluxDeploymentManager, 'delete_oci_repository_crd',
                       return_value=True)
    @mock.patch.object(flux.FluxDeploymentManager, 'get_chart_path',
                       return_value='/charts/flux2-2.18.0.tgz')
    def test_upgrade_success(self, mock_chart_path, mock_delete_crd,
                             mock_download, mock_overrides, mock_run):
        """Returns True on successful upgrade."""
        result = self.manager.upgrade_controllers()
        self.assertTrue(result)
        self.assertEqual(mock_run.call_count, 2)  # flux migrate + helm upgrade

    @mock.patch.object(flux.FluxDeploymentManager, 'get_chart_path',
                       return_value=None)
    def test_upgrade_no_chart(self, mock_chart_path):
        """Returns False when chart is not found."""
        result = self.manager.upgrade_controllers()
        self.assertFalse(result)

    @mock.patch.object(flux.FluxDeploymentManager, 'delete_oci_repository_crd',
                       return_value=True)
    @mock.patch.object(flux.FluxDeploymentManager, 'download_images',
                       return_value=False)
    @mock.patch.object(flux.FluxDeploymentManager, 'get_chart_path',
                       return_value='/charts/flux2-2.18.0.tgz')
    def test_upgrade_download_failure(self, mock_chart_path,
                                      mock_download, mock_delete_crd):
        """Returns False when image download fails."""
        result = self.manager.upgrade_controllers()
        self.assertFalse(result)

    @mock.patch('subprocess.run',
                side_effect=subprocess.CalledProcessError(1, 'helm', stderr='error'))
    @mock.patch.object(flux.FluxDeploymentManager, 'generate_overrides',
                       return_value='overrides_content')
    @mock.patch.object(flux.FluxDeploymentManager, 'download_images',
                       return_value=True)
    @mock.patch.object(flux.FluxDeploymentManager, 'delete_oci_repository_crd',
                       return_value=True)
    @mock.patch.object(flux.FluxDeploymentManager, 'get_chart_path',
                       return_value='/charts/flux2-2.18.0.tgz')
    def test_upgrade_helm_failure(self, mock_chart_path, mock_delete_crd,
                                  mock_download, mock_overrides, mock_run):
        """Returns False when helm upgrade command fails."""
        result = self.manager.upgrade_controllers()
        self.assertFalse(result)


class TestRollbackControllers(TestFluxDeploymentManagerBase):
    """Tests for FluxDeploymentManager.rollback_controllers()."""

    @mock.patch('subprocess.run')
    @mock.patch.object(flux.FluxDeploymentManager, 'wait_helm_controller_pod_ready')
    @mock.patch.object(flux.FluxDeploymentManager, 'delete_oci_repository_crd',
                       return_value=True)
    @mock.patch('sysinv.helm.utils.get_history', return_value=FAKE_HISTORY)
    @mock.patch('sysinv.helm.utils.get_chart_version', return_value='2.15.0')
    @mock.patch.object(flux.FluxDeploymentManager, 'get_chart_path')
    def test_rollback_success(self, mock_chart_path, mock_version,
                              mock_history, mock_delete_crd,
                              mock_wait_pod, mock_run):
        """Returns True on successful rollback."""
        mock_chart_path.side_effect = [
            '/ostree/2/charts/flux2-2.15.0.tgz',  # previous
            '/charts/flux2-2.18.0.tgz',            # current
        ]
        result = self.manager.rollback_controllers()
        self.assertTrue(result)
        mock_run.assert_called_once()

    @mock.patch.object(flux.FluxDeploymentManager, 'get_chart_path',
                       return_value=None)
    def test_rollback_no_previous_chart(self, mock_chart_path):
        """Returns False when no previous chart is found."""
        result = self.manager.rollback_controllers()
        self.assertFalse(result)

    @mock.patch('sysinv.helm.utils.get_history', return_value=FAKE_HISTORY)
    @mock.patch('sysinv.helm.utils.get_chart_version', return_value='2.18.0')
    @mock.patch.object(flux.FluxDeploymentManager, 'get_chart_path')
    def test_rollback_same_version_skips(self, mock_chart_path,
                                         mock_version, mock_history):
        """Returns True and skips when previous and current are the same."""
        mock_chart_path.side_effect = [
            '/ostree/2/charts/flux2-2.18.0.tgz',  # previous
            '/charts/flux2-2.18.0.tgz',            # current
        ]
        result = self.manager.rollback_controllers()
        self.assertTrue(result)

    @mock.patch.object(flux.FluxDeploymentManager, 'delete_oci_repository_crd',
                       return_value=True)
    @mock.patch('sysinv.helm.utils.get_history')
    @mock.patch('sysinv.helm.utils.get_chart_version', return_value='2.15.0')
    @mock.patch.object(flux.FluxDeploymentManager, 'get_chart_path')
    def test_rollback_already_at_target(self, mock_chart_path,
                                        mock_version, mock_history,
                                        mock_delete_crd):
        """Returns True when target version is already installed."""
        mock_chart_path.side_effect = [
            '/ostree/2/charts/flux2-2.15.0.tgz',
            '/charts/flux2-2.18.0.tgz',
        ]
        mock_history.return_value = [
            {"chart": "flux2-2.18.0", "revision": 1, "status": "superseded"},
            {"chart": "flux2-2.15.0", "revision": 2, "status": "deployed"},
        ]
        result = self.manager.rollback_controllers()
        self.assertTrue(result)

    @mock.patch.object(flux.FluxDeploymentManager, 'delete_oci_repository_crd',
                       return_value=True)
    @mock.patch('sysinv.helm.utils.get_history', return_value=FAKE_HISTORY)
    @mock.patch('sysinv.helm.utils.get_chart_version', return_value='2.10.0')
    @mock.patch.object(flux.FluxDeploymentManager, 'get_chart_path')
    def test_rollback_target_not_in_history(self, mock_chart_path,
                                            mock_version, mock_history,
                                            mock_delete_crd):
        """Returns True when target version has no revision in history."""
        mock_chart_path.side_effect = [
            '/ostree/2/charts/flux2-2.10.0.tgz',
            '/charts/flux2-2.18.0.tgz',
        ]
        result = self.manager.rollback_controllers()
        self.assertTrue(result)

    @mock.patch('subprocess.run',
                side_effect=subprocess.CalledProcessError(1, 'helm', stderr='error'))
    @mock.patch.object(flux.FluxDeploymentManager, 'wait_helm_controller_pod_ready')
    @mock.patch.object(flux.FluxDeploymentManager, 'delete_oci_repository_crd',
                       return_value=True)
    @mock.patch('sysinv.helm.utils.get_history', return_value=FAKE_HISTORY)
    @mock.patch('sysinv.helm.utils.get_chart_version', return_value='2.15.0')
    @mock.patch.object(flux.FluxDeploymentManager, 'get_chart_path')
    def test_rollback_helm_failure(self, mock_chart_path, mock_version,
                                   mock_history, mock_delete_crd,
                                   mock_wait_pod, mock_run):
        """Returns False when helm rollback command fails."""
        mock_chart_path.side_effect = [
            '/ostree/2/charts/flux2-2.15.0.tgz',
            '/charts/flux2-2.18.0.tgz',
        ]
        result = self.manager.rollback_controllers()
        self.assertFalse(result)


class TestDeployControllers(TestFluxDeploymentManagerBase):
    """Tests for FluxDeploymentManager.deploy_controllers()."""

    @mock.patch('subprocess.run')
    @mock.patch('sysinv.common.utils.get_local_docker_registry_auth',
                return_value={'username': 'admin', 'password': 'secret'})
    @mock.patch('sysinv.common.kubernetes.KubeOperator')
    @mock.patch.object(flux.FluxDeploymentManager, 'generate_overrides',
                       return_value='overrides_content')
    @mock.patch.object(flux.FluxDeploymentManager, 'download_images',
                       return_value=True)
    @mock.patch.object(flux.FluxDeploymentManager, 'get_chart_path',
                       return_value='/charts/flux2-2.18.0.tgz')
    def test_deploy_success(self, mock_chart_path, mock_download,
                            mock_overrides, mock_kube_cls,
                            mock_registry_auth, mock_run):
        """Returns True on successful deployment."""
        result = self.manager.deploy_controllers()
        self.assertTrue(result)
        mock_run.assert_called_once()

    @mock.patch.object(flux.FluxDeploymentManager, 'get_chart_path',
                       return_value=None)
    def test_deploy_no_chart(self, mock_chart_path):
        """Returns False when chart is not found."""
        result = self.manager.deploy_controllers()
        self.assertFalse(result)

    @mock.patch.object(flux.FluxDeploymentManager, 'download_images',
                       return_value=False)
    @mock.patch.object(flux.FluxDeploymentManager, 'get_chart_path',
                       return_value='/charts/flux2-2.18.0.tgz')
    def test_deploy_download_failure(self, mock_chart_path, mock_download):
        """Returns False when image download fails."""
        result = self.manager.deploy_controllers()
        self.assertFalse(result)

    @mock.patch('subprocess.run')
    @mock.patch('sysinv.common.utils.get_local_docker_registry_auth',
                return_value={'username': 'admin', 'password': 'secret'})
    @mock.patch('sysinv.common.kubernetes.KubeOperator')
    @mock.patch.object(flux.FluxDeploymentManager, 'generate_overrides',
                       return_value='overrides_content')
    @mock.patch.object(flux.FluxDeploymentManager, 'download_images',
                       return_value=True)
    @mock.patch.object(flux.FluxDeploymentManager, 'get_chart_path',
                       return_value='/charts/flux2-2.18.0.tgz')
    def test_deploy_skip_download(self, mock_chart_path, mock_download,
                                  mock_overrides, mock_kube_cls,
                                  mock_registry_auth, mock_run):
        """Does not download images when download_images=False."""
        result = self.manager.deploy_controllers(download_images=False)
        self.assertTrue(result)
        mock_download.assert_not_called()

    @mock.patch('subprocess.run',
                side_effect=subprocess.CalledProcessError(1, 'helm', stderr='error'))
    @mock.patch('sysinv.common.utils.get_local_docker_registry_auth',
                return_value={'username': 'admin', 'password': 'secret'})
    @mock.patch('sysinv.common.kubernetes.KubeOperator')
    @mock.patch.object(flux.FluxDeploymentManager, 'generate_overrides',
                       return_value='overrides_content')
    @mock.patch.object(flux.FluxDeploymentManager, 'download_images',
                       return_value=True)
    @mock.patch.object(flux.FluxDeploymentManager, 'get_chart_path',
                       return_value='/charts/flux2-2.18.0.tgz')
    def test_deploy_helm_failure(self, mock_chart_path, mock_download,
                                 mock_overrides, mock_kube_cls,
                                 mock_registry_auth, mock_run):
        """Returns False when helm install command fails."""
        result = self.manager.deploy_controllers()
        self.assertFalse(result)


class TestDeployControllersRestore(TestFluxDeploymentManagerBase):
    """Tests for FluxDeploymentManager.deploy_controllers_restore()."""

    @mock.patch('subprocess.run')
    @mock.patch.object(flux.FluxDeploymentManager, 'deploy_controllers',
                       return_value=True)
    @mock.patch.object(flux.FluxDeploymentManager, 'generate_overrides',
                       return_value='overrides_content')
    @mock.patch.object(flux.FluxDeploymentManager, 'get_chart_path',
                       return_value='/charts/flux2-2.18.0.tgz')
    @mock.patch('sysinv.common.kubernetes.KubeOperator')
    def test_restore_success(self, mock_kube_cls, mock_chart_path,
                             mock_overrides, mock_deploy, mock_run):
        """Returns True on full successful restore flow."""
        mock_kube = mock_kube_cls.return_value
        mock_kube.kube_namespaced_pods_exist.return_value = True
        result = self.manager.deploy_controllers_restore()
        self.assertTrue(result)
        mock_deploy.assert_called_once_with(download_images=True)
        # scale-down helm + final upgrade helm = 2 subprocess.run calls
        self.assertEqual(mock_run.call_count, 2)

    @mock.patch.object(flux.FluxDeploymentManager, 'deploy_controllers',
                       return_value=True)
    @mock.patch('sysinv.common.kubernetes.KubeOperator')
    def test_restore_no_pods_skips_scale_down(self, mock_kube_cls,
                                              mock_deploy):
        """Skips scale-down and calls deploy_controllers directly
        when no pods exist in the namespace."""
        mock_kube = mock_kube_cls.return_value
        mock_kube.kube_namespaced_pods_exist.return_value = False
        result = self.manager.deploy_controllers_restore()
        self.assertTrue(result)
        mock_deploy.assert_called_once_with(download_images=True)

    @mock.patch.object(flux.FluxDeploymentManager, 'deploy_controllers',
                       return_value=True)
    @mock.patch('sysinv.common.kubernetes.KubeOperator')
    def test_restore_no_pods_skip_download(self, mock_kube_cls,
                                           mock_deploy):
        """Passes download_images=False when specified."""
        mock_kube = mock_kube_cls.return_value
        mock_kube.kube_namespaced_pods_exist.return_value = False
        result = self.manager.deploy_controllers_restore(download_images=False)
        self.assertTrue(result)
        mock_deploy.assert_called_once_with(download_images=False)

    @mock.patch.object(flux.FluxDeploymentManager, 'generate_overrides',
                       return_value='overrides_content')
    @mock.patch.object(flux.FluxDeploymentManager, 'get_chart_path',
                       return_value=None)
    @mock.patch('sysinv.common.kubernetes.KubeOperator')
    def test_restore_no_chart_for_scale_down(self, mock_kube_cls,
                                             mock_chart_path,
                                             mock_overrides):
        """Returns False when chart is not found for scale-down."""
        mock_kube = mock_kube_cls.return_value
        mock_kube.kube_namespaced_pods_exist.return_value = True
        result = self.manager.deploy_controllers_restore()
        self.assertFalse(result)

    @mock.patch('subprocess.run',
                side_effect=subprocess.CalledProcessError(
                    1, 'helm', stderr='scale down failed'))
    @mock.patch.object(flux.FluxDeploymentManager, 'generate_overrides',
                       return_value='overrides_content')
    @mock.patch.object(flux.FluxDeploymentManager, 'get_chart_path',
                       return_value='/charts/flux2-2.18.0.tgz')
    @mock.patch('sysinv.common.kubernetes.KubeOperator')
    def test_restore_scale_down_failure(self, mock_kube_cls,
                                        mock_chart_path, mock_overrides,
                                        mock_run):
        """Returns False when scale-down helm upgrade fails."""
        mock_kube = mock_kube_cls.return_value
        mock_kube.kube_namespaced_pods_exist.return_value = True
        result = self.manager.deploy_controllers_restore()
        self.assertFalse(result)

    @mock.patch('subprocess.run')
    @mock.patch.object(flux.FluxDeploymentManager, 'deploy_controllers',
                       return_value=False)
    @mock.patch.object(flux.FluxDeploymentManager, 'generate_overrides',
                       return_value='overrides_content')
    @mock.patch.object(flux.FluxDeploymentManager, 'get_chart_path',
                       return_value='/charts/flux2-2.18.0.tgz')
    @mock.patch('sysinv.common.kubernetes.KubeOperator')
    def test_restore_deploy_controllers_failure(self, mock_kube_cls,
                                                mock_chart_path,
                                                mock_overrides,
                                                mock_deploy, mock_run):
        """Returns False when deploy_controllers fails after scale-down."""
        mock_kube = mock_kube_cls.return_value
        mock_kube.kube_namespaced_pods_exist.return_value = True
        result = self.manager.deploy_controllers_restore()
        self.assertFalse(result)
        mock_deploy.assert_called_once()

    @mock.patch.object(flux.FluxDeploymentManager, 'deploy_controllers',
                       return_value=True)
    @mock.patch.object(flux.FluxDeploymentManager, 'generate_overrides',
                       return_value='overrides_content')
    @mock.patch.object(flux.FluxDeploymentManager, 'get_chart_path',
                       return_value='/charts/flux2-2.18.0.tgz')
    @mock.patch('sysinv.common.kubernetes.KubeOperator')
    def test_restore_final_upgrade_failure(self, mock_kube_cls,
                                           mock_chart_path,
                                           mock_overrides, mock_deploy):
        """Returns False when the final helm upgrade fails."""
        mock_kube = mock_kube_cls.return_value
        mock_kube.kube_namespaced_pods_exist.return_value = True

        # First subprocess.run (scale-down) succeeds, second (final upgrade) fails
        with mock.patch('subprocess.run') as mock_run:
            mock_run.side_effect = [
                None,  # scale-down succeeds
                subprocess.CalledProcessError(1, 'helm', stderr='upgrade failed'),
            ]
            result = self.manager.deploy_controllers_restore()
        self.assertFalse(result)
