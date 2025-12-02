#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import sys
import types
import unittest
from importlib import metadata as metadata_importlib
from unittest import mock

from sysinv.common.plugin_manager import PLUGIN_NS_HELM_APPLICATIONS
from sysinv.common.plugin_manager import PLUGIN_NS_KUSTOMIZE_OPS
from sysinv.common.plugin_manager import PLUGIN_NS_LIFECYCLE_OPS
from sysinv.common.plugin_manager import Plugin
from sysinv.common.plugin_manager import PluginManager
from sysinv.helm.common import APP_PTH_PREFIX
from sysinv.helm.common import APP_PLUGIN_PATH


class FakePlugin:  # noqa: H238
    @classmethod
    def load(cls):
        return cls


class TestPluginManager(unittest.TestCase):
    def setUp(self):
        self.manager = PluginManager()

    def test_namespace_accept_args_return_true_only_to_valid_namespaces(self):
        self.assertTrue(self.manager._namespace_accept_args("systemconfig.helm_applications"))
        self.assertTrue(self.manager._namespace_accept_args("systemconfig.helm_plugins"))
        self.assertTrue(self.manager._namespace_accept_args("systemconfig.puppet_plugins"))
        self.assertFalse(self.manager._namespace_accept_args("systemconfig.app_lifecycle"))

    def test_has_subnamespace_returns_true_only_to_namespaces_with_subns(self):
        self.assertTrue(self.manager._has_subnamespace("systemconfig.helm_applications"))
        self.assertFalse(self.manager._has_subnamespace("systemconfig.app_lifecycle"))

    def test_is_subnamespace_returns_true_only_to_subnamespaces(self):
        self.assertTrue(self.manager._is_subnamespace("systemconfig.helm_plugins"))
        self.assertFalse(self.manager._is_subnamespace("systemconfig.helm_applications"))

    def test_get_parent_namespace_return_right_subnamespace(self):
        parent = self.manager._get_parent_namespace("systemconfig.helm_plugins")
        self.assertEqual(parent, "systemconfig.helm_applications")

    @mock.patch("sysinv.common.plugin_manager.metadata_importlib.distribution")
    def test_get_project_name_and_location(self, mock_dist):
        mock_dist.return_value.metadata.get.return_value = "mock_project"
        mock_dist.return_value.locate_file.return_value = "/opt/plugins/mock_project"
        fake_module = types.ModuleType("fake.mod")
        with mock.patch.dict("sys.modules", {"fake": fake_module}):
            project_name, project_path = self.manager._get_project_name_and_location(fake_module)
        self.assertEqual(project_name, "mock_project")
        self.assertEqual(project_path, "/opt/plugins/mock_project")

    @mock.patch("sysinv.common.plugin_manager.pkg_resources.get_distribution")
    @mock.patch("sysinv.common.plugin_manager.metadata_importlib.distribution")
    def test_get_project_name_and_location_pkg_resources_fallback(
        self,
        mock_importlib_dist,
        mock_pkg_resources_dist
    ):
        mock_importlib_dist.side_effect = metadata_importlib.PackageNotFoundError
        mock_pkg_dist_obj = mock.Mock()
        mock_pkg_dist_obj.project_name = "fallback_project"
        mock_pkg_dist_obj.location = "/opt/plugins/fallback_project"
        mock_pkg_resources_dist.return_value = mock_pkg_dist_obj

        fake_module = types.ModuleType("modtest")
        fake_module.__name__ = "modtest"
        with mock.patch.dict("sys.modules", {"modtest": fake_module}):
            project_name, project_path = self.manager._get_project_name_and_location(
                fake_module
            )
        self.assertEqual(project_name, "fallback_project")
        self.assertEqual(project_path, "/opt/plugins/fallback_project")
        mock_pkg_resources_dist.assert_called_once_with("modtest")

    def test_get_plugins_by_project_path_return_only_plugins_from_right_path(self):
        fake_1 = Plugin(name="a1", project_name="p1", project_path="/opt/p1", operator=None)
        fake_2 = Plugin(name="a2", project_name="p2", project_path="/opt/p2", operator=None)
        fake_3 = Plugin(name="b1", project_name="p1", project_path="/opt/p1", operator=None)

        self.manager._plugins = {
            "fake_namespace_1": {"a1": fake_1, "a2": fake_2},
            "fake_namespace_2": {"b1": fake_3},
        }
        result = self.manager._get_plugins_by_project_path("/opt/p1")

        self.assertIn("fake_namespace_1", result)
        self.assertIn("fake_namespace_2", result)
        self.assertEqual(result["fake_namespace_1"], [fake_1, ])
        self.assertEqual(result["fake_namespace_2"], [fake_3, ])

    @mock.patch("sysinv.common.plugin_manager.metadata_importlib.entry_points")
    @mock.patch.object(PluginManager, "_get_project_name_and_location",
                       return_value=("fake_project", "/tmp/fake/path"))
    def test_load_plugins_correctly_loads_a_plugin(self, mock_get_proj, mock_entry_point):
        fake_ep = mock.Mock()
        fake_ep.name = "fake_plugin"
        fake_ep.load.return_value = lambda: "RESULT"
        mock_entry_point.return_value.get.return_value = [fake_ep]

        plugins = self.manager.load_plugins("systemconfig.app_lifecycle")
        self.assertIn("fake_plugin", plugins)
        self.assertIn("fake_plugin", self.manager._plugins["systemconfig.app_lifecycle"])
        self.assertIsInstance(plugins["fake_plugin"], Plugin)

    @mock.patch("sysinv.common.plugin_manager.metadata_importlib.entry_points")
    @mock.patch.object(PluginManager, "_get_project_name_and_location",
                       return_value=("fake_project", "/tmp/fake/path"))
    def test_invoke_on_load_true_returns_an_instance_to_operator_attr(
        self,
        mock_get_proj,
        mock_entry_point
    ):
        fake_ep = mock.Mock()
        fake_ep.name = "fake_plugin"
        fake_ep.load.return_value = FakePlugin
        mock_entry_point.return_value.get.return_value = [fake_ep]
        plugins = self.manager.load_plugins("systemconfig.app_lifecycle", invoke_on_load=True)
        self.assertIsInstance(plugins["fake_plugin"].operator, FakePlugin)

    @mock.patch("sysinv.common.plugin_manager.metadata_importlib.entry_points")
    @mock.patch.object(PluginManager, "_get_project_name_and_location",
                       return_value=("fake_project", "/tmp/fake/path"))
    def test_invoke_on_load_false_returns_a_class_to_operator_attr(
        self,
        mock_get_proj,
        mock_entry_point
    ):
        fake_ep = mock.Mock()
        fake_ep.name = "fake_plugin"
        fake_ep.load.return_value = FakePlugin
        mock_entry_point.return_value.get.return_value = [fake_ep]
        plugins = self.manager.load_plugins("systemconfig.app_lifecycle", invoke_on_load=False)
        self.assertIs(plugins["fake_plugin"].operator, FakePlugin)
        self.assertNotIsInstance(plugins["fake_plugin"].operator, FakePlugin)

    @mock.patch("sysinv.common.plugin_manager.metadata_importlib.entry_points")
    @mock.patch.object(PluginManager, "_get_project_name_and_location",
                       return_value=("fake_project", "/tmp/path"))
    def test_plugins_are_loaded_in_order(self, mock_get_proj, mock_entry_point):
        fake_ep_a = mock.Mock()
        fake_ep_a.name = "001_plugin_a"
        fake_ep_a.load.return_value = lambda: "A"

        fake_ep_b = mock.Mock()
        fake_ep_b.name = "002_plugin_b"
        fake_ep_b.load.return_value = lambda: "B"

        fake_ep_c = mock.Mock()
        fake_ep_c.name = "003_plugin_c"
        fake_ep_c.load.return_value = lambda: "C"
        mock_entry_point.return_value.get.return_value = [fake_ep_b, fake_ep_a, fake_ep_c]

        plugins = self.manager.load_plugins("systemconfig.app_lifecycle")
        expected_order = ["plugin_a", "plugin_b", "plugin_c"]
        self.assertListEqual(list(plugins.keys()), expected_order)

    @mock.patch.object(PluginManager, "load_plugins")
    def test_discover_plugins_calls_load_plugins_for_all_namespaces(self, mock_load_plugins):
        self.manager.discover_plugins()
        expected_namespaces = [
            PLUGIN_NS_HELM_APPLICATIONS,
            PLUGIN_NS_KUSTOMIZE_OPS,
            PLUGIN_NS_LIFECYCLE_OPS,
        ]
        self.assertEqual(mock_load_plugins.call_count, 3)
        expected_calls = [mock.call(namespace=ns, args=()) for ns in expected_namespaces]
        mock_load_plugins.assert_has_calls(expected_calls, any_order=False)

    @mock.patch.object(PluginManager, "load_plugins")
    def test_discover_plugins_clears_internal_dicts(self, mock_load_plugins):
        self.manager._plugins = {"old_ns": {"fake_plugin": "OLD"}}
        self.manager._subnamespace_plugins = {"old_ns": {"fake_plugin": ["OLD"]}}
        self.manager.discover_plugins()
        self.assertEqual(self.manager._plugins, {})
        self.assertEqual(self.manager._subnamespace_plugins, {})

    @mock.patch("sysinv.common.plugin_manager.open", create=True)
    @mock.patch("sysinv.common.plugin_manager.os.path.isfile")
    @mock.patch("sysinv.common.plugin_manager.site.addsitedir")
    @mock.patch("sysinv.common.plugin_manager.PluginManager.load_plugins_from_path")
    def test_activate_plugins_correctly_activate_and_load_the_plugins(
        self,
        mock_load,
        mock_addsite,
        mock_isfile,
        mock_open
    ):
        app_name = "testapp"
        version = "1.0"
        sync_dir = "/tmp/plugins/test"
        mock_isfile.return_value = False

        self.manager.activate_plugins(
            app_name,
            version,
            has_plugin_path=True,
            sync_plugins_dir=sync_dir
        )
        expected_pth = f"{APP_PLUGIN_PATH}/{APP_PTH_PREFIX}{app_name}-{version}.pth"
        mock_open.assert_called_with(expected_pth, 'w')
        mock_addsite.assert_called_with(sync_dir)
        mock_load.assert_called_with(plugin_path=sync_dir, args=())
        expected_order = [
            mock.call.addsitedir(sync_dir),
            mock.call.load_plugins_from_path(plugin_path=sync_dir, args=()),
        ]
        combined_calls = mock_addsite.mock_calls + mock_load.mock_calls
        self.assertEqual(combined_calls, expected_order)

    @mock.patch("sysinv.common.plugin_manager.os.path.exists", return_value=True)
    @mock.patch("sysinv.common.plugin_manager.os.remove")
    def test_deactivate_plugins_removes_pth_and_modules(self, mock_rm, mock_exists):
        app_name = "test"
        version = "1.0"
        sync_dir = "/tmp/plugins/test"
        namespace = "systemconfig.helm_applications"
        fake_plugin = Plugin(
            name="fake_plugin",
            project_name="fake_project",
            project_path=sync_dir,
            operator=None,
        )
        self.manager._plugins = {namespace: {"fake_plugin": fake_plugin}}
        self.manager._subnamespace_plugins = {namespace: {"fake_plugin": ["fake_subplugin"]}}

        with mock.patch.object(
            self.manager,
            "_get_plugins_by_project_path",
            return_value={namespace: [fake_plugin]},
        ):
            fake_mod = types.ModuleType("mod1")
            fake_mod.__file__ = "/tmp/plugins/test/foo.py"
            with mock.patch.dict("sys.modules", {"mod1": fake_mod}):
                self.manager.deactivate_plugins(
                    app_name, version, has_plugin_path=True, sync_plugins_dir=sync_dir
                )

        self.assertNotIn("mod1", sys.modules)
        expected_pth = f"{APP_PLUGIN_PATH}/{APP_PTH_PREFIX}{app_name}-{version}.pth"
        mock_rm.assert_called_with(expected_pth)
        self.assertNotIn("fake_plugin", self.manager._plugins[namespace])
        self.assertNotIn("fake_plugin", self.manager._subnamespace_plugins[namespace])

    @mock.patch("sysinv.common.plugin_manager.zipfile.ZipFile")
    @mock.patch("sysinv.common.plugin_manager.os.makedirs")
    @mock.patch("sysinv.common.plugin_manager.os.path.isdir", return_value=False)
    @mock.patch("sysinv.common.plugin_manager.glob.glob")
    def test_install_plugins_extracts_wheels(self, mock_glob, mock_isdir, mock_makedirs, mock_zip):
        app_name = "testapp"
        inst_dir = "/tmp/install"
        sync_dir = "/tmp/sync"
        mock_glob.return_value = [
            "/tmp/install/plugin1.whl",
            "/tmp/install/plugin2.whl"
        ]
        PluginManager.install_plugins(app_name, inst_dir, sync_dir)
        mock_makedirs.assert_called_once_with(sync_dir)
        expected_calls = [
            mock.call("/tmp/install/plugin1.whl"),
            mock.call().__enter__(),
            mock.call().__enter__().extractall(sync_dir),
            mock.call().__exit__(None, None, None),
            mock.call("/tmp/install/plugin2.whl"),
            mock.call().__enter__(),
            mock.call().__enter__().extractall(sync_dir),
            mock.call().__exit__(None, None, None),
        ]
        self.assertEqual(mock_zip.mock_calls, expected_calls)

    @mock.patch("sysinv.common.plugin_manager.shutil.rmtree")
    @mock.patch("sysinv.common.plugin_manager.os.path.isdir", return_value=True)
    def test_uninstall_plugins_removes_directory(self, mock_isdir, mock_rmtree):
        sync_dir = "/tmp/plugins/test"
        PluginManager.uninstall_plugins(sync_dir)
        mock_isdir.assert_called_once_with(sync_dir)
        mock_rmtree.assert_called_once_with(sync_dir)

    def test_get_plugin_returns_right_plugin_or_a_generic_as_fallback(self):
        self.manager._plugins["ns"] = {
            "generic": Plugin("generic", "pkg", "/tmp", None),
            "fake_1": Plugin("fake_1", "pkg", "/tmp", None),
        }
        plugin = self.manager.get_plugin("ns", "fake_1")
        self.assertEqual(plugin.name, "fake_1")
        plugin = self.manager.get_plugin("ns", "missing")
        self.assertEqual(plugin.name, "generic")

    def test_get_plugin_returns_None_when_fallback_is_false(self):
        self.manager._plugins["ns"] = {"generic": Plugin("generic", "pkg", "/tmp", None)}
        plugin = self.manager.get_plugin("ns", "fake_1", fallback_to_generic=False)
        self.assertEqual(plugin, None)

    @mock.patch("sysinv.common.plugin_manager.HELM_OVERRIDES_PATH", "/opt/platform/helm_overrides")
    @mock.patch("sysinv.common.plugin_manager.os.remove")
    @mock.patch("sysinv.common.plugin_manager.open", create=True)
    @mock.patch("sysinv.common.plugin_manager.glob.glob")
    def test_audit_plugins_removes_pth_from_invalid_versions(
        self, mock_glob, mock_open, mock_remove
    ):
        pth_file = "/etc/platform/plugins/enable/testapp-1.0-1.pth"
        plugin_folder = "/opt/platform/helm_overrides/testapp/1.0-1/plugins"
        mock_glob.return_value = [pth_file]
        fake_file = mock.mock_open(read_data=plugin_folder + "\n")
        mock_open.side_effect = fake_file
        dbapi = mock.Mock()
        dbapi.kube_app_get.return_value = mock.Mock(app_version="2.0-1")

        fake_sys_path = [plugin_folder]
        with mock.patch("sysinv.common.plugin_manager.sys.path", fake_sys_path):
            PluginManager.audit_plugins(PluginManager, dbapi)

        mock_glob.assert_called_once()
        self.assertNotIn(plugin_folder, fake_sys_path)
        mock_remove.assert_called_once_with(pth_file)
        dbapi.kube_app_get.assert_called_once_with("testapp")


if __name__ == "__main__":
    unittest.main()
