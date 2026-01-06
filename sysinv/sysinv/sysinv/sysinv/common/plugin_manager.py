#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""PluginManager: Manages dynamic plugins for system applications.

This class handles discovery, loading, activation, and deactivation of application plugins.
It manages plugins by namespace, supports subnamespaces, and ensures that only valid and enabled
plugins are loaded.

Some routines interact directly with python's module cache (sys.modules) to safely remove modules
from previously activated plugin directories, preventing stale or conflicting plugin code from
being used.

Public API methods expose functionality for loading, activating, deactivating, installing,
uninstalling, and auditing plugins for intended applications.
"""


import glob
import os
import re
import shutil
import site
import sys
import types
import zipfile
from dataclasses import dataclass
from importlib import metadata as metadata_importlib

import pkg_resources
from oslo_log import log as logging

from sysinv.common.exception import KubeAppNotFound
from sysinv.common.exception import SysinvException
from sysinv.helm.common import APP_PLUGIN_PATH
from sysinv.helm.common import APP_PTH_PREFIX
from sysinv.helm.common import HELM_OVERRIDES_PATH


LOG = logging.getLogger(__name__)

PLUGIN_NS_HELM_APPLICATIONS = 'systemconfig.helm_applications'
PLUGIN_SUBNS_HELM_APPLICATIONS = 'systemconfig.helm_plugins'
PLUGIN_NS_KUSTOMIZE_OPS = 'systemconfig.fluxcd.kustomize_ops'
PLUGIN_NS_LIFECYCLE_OPS = 'systemconfig.app_lifecycle'
PLUGIN_NS_PUPPET_OPS = 'systemconfig.puppet_plugins'

ACCEPT_ARGUMENTS_NAMESPACES = (
    PLUGIN_NS_HELM_APPLICATIONS,
    PLUGIN_SUBNS_HELM_APPLICATIONS,
    PLUGIN_NS_PUPPET_OPS
)

NAMESPACE_AND_SUBNAMESPACE_RELATION = {
    PLUGIN_NS_HELM_APPLICATIONS: (PLUGIN_SUBNS_HELM_APPLICATIONS,),
}


@dataclass
class Plugin:  # noqa: H238
    name: str
    project_name: str
    project_path: str
    operator: object


class PluginManager:  # noqa: H238
    def __init__(self, order=True):
        self._plugins = {}
        self._subnamespace_plugins = {}
        self._order = order

    @staticmethod
    def _namespace_accept_args(namespace):
        return namespace.startswith(ACCEPT_ARGUMENTS_NAMESPACES)

    @staticmethod
    def _has_subnamespace(namespace):
        for ns in NAMESPACE_AND_SUBNAMESPACE_RELATION:
            if namespace.startswith(ns):
                return True
        return False

    @staticmethod
    def _is_subnamespace(namespace):
        for sub_namespaces in NAMESPACE_AND_SUBNAMESPACE_RELATION.values():
            if namespace.startswith(sub_namespaces):
                return True
        return False

    @staticmethod
    def _get_parent_namespace(sub_namespace):
        for parent, sub_namespaces in NAMESPACE_AND_SUBNAMESPACE_RELATION.items():
            if sub_namespace.startswith(sub_namespaces):
                return parent

    @staticmethod
    def _get_project_name_and_location(loaded_entrypoint):
        """
            Returns the name and path of the python project associated with a loaded entrypoint.
            Attempts to determine the module's distribution using importlib.metadata or
            pkg_resources.

            :param loaded_entrypoint (module or callable): The loaded module or entrypoint object.
            :return (tuple): A tuple containing project_name and project_path.
        """
        # TODO(edias): entrypoints from importlib with python ≥ 3.10 already have a distribution
        # attribute, so the code below will not be necessary in future releases.
        if isinstance(loaded_entrypoint, types.ModuleType):
            module = loaded_entrypoint
        else:
            module = sys.modules[loaded_entrypoint.__module__]

        module_name = module.__name__.split('.')[0]
        try:
            distribution = metadata_importlib.distribution(module_name)
            project_name = distribution.metadata.get('Name')
            project_location = str(distribution.locate_file(''))
        except metadata_importlib.PackageNotFoundError:
            try:
                # Some distributions may not be found using importlib due to the actual packaging
                # process with setuptools and dh_python, or if it’s a development package.
                # In this case, the system tries to find the distribution through the pkg_resources
                # library.
                distribution = pkg_resources.get_distribution(module_name)
                root_prefix = "/var/rootdirs"
                project_name = distribution.project_name
                project_location = distribution.location
                if project_location.startswith(root_prefix):
                    project_location = project_location[len(root_prefix):]
                    project_location = os.path.normpath(project_location)
            except Exception as e:
                LOG.error(e)
                raise SysinvException(f"Could not find distribution for {module_name}")
        except Exception as e:
            LOG.error(e)
            raise SysinvException(f"Could not find distribution for {module_name}")
        return (project_name, project_location)

    def _get_plugins_by_project_path(self, path):
        """Returns all plugins whose project path matches the given path"""
        path_plugins = {}
        for namespace, plugins in self._plugins.items():
            matching = [p for p in plugins.values() if p.project_path == path]
            if matching:
                path_plugins[namespace] = matching
        return path_plugins

    def _load_entrypoints(self, entrypoints, namespace, invoke_on_load, args):
        """
            Loads plugins from the given entrypoints for a specific namespace.
            Handles subnamespaces by recursively loading their plugins. If `invoke_on_load` is
            True, the entrypoint callable is executed with the provided arguments. Otherwise, the
            entrypoint itself is stored.

            :param entrypoints (list): list of entrypoint objects to load.
            :param namespace (str): the namespace under which to register the loaded plugins.
            :param invoke_on_load (bool): whether to call the entrypoint immediately upon loading.
            :param args (tuple): arguments to pass to the entrypoint if invoked.
            :return (dict): a dictionary mapping plugin names to plugin objects that were loaded.
        """
        args = () if not self._namespace_accept_args(namespace) else args
        loaded_plugins = {}
        ns = namespace

        if self._is_subnamespace(namespace):
            ns = self._get_parent_namespace(namespace)

        if self._has_subnamespace(namespace):
            # Some entrypoints pointed not to a plugin path, but rather to other namespaces.
            # In this cases, the system gets the subnamespaces entrypoints and recursively load
            # the entrypoints.
            for entrypoint in entrypoints:
                sub_namespace = entrypoint.value
                plugins = self.load_plugins(sub_namespace, invoke_on_load, args)
                self._subnamespace_plugins.setdefault(namespace, {})[entrypoint.name] = [
                    sub_entrypoint_name for sub_entrypoint_name in plugins
                ]
                loaded_plugins.update(plugins)
            return loaded_plugins

        if self._order:
            entrypoints = sorted(entrypoints, key=lambda e: e.name)

        for entrypoint in entrypoints:
            loaded_entrypoint = entrypoint.load()
            project_name, project_path = self._get_project_name_and_location(loaded_entrypoint)
            # In order to control the order of the plugins without changing their names, some
            # plugins use a prefix following the pattern '###__PLUGINNAME'. Also to allow
            # overriding with a newer version of the AppLifecycle operator, some plugins have the
            # convention to use an optional suffix with the pattern 'PLUGINNAME_###'. As the
            # entry points have already been ordered, the regex below removes both, prefix and
            # suffix if they exist.
            plugin_name = re.sub(r'^(?:\d{3}_)?(.*?)(?:_\d{3})?$', r'\1', entrypoint.name)
            loaded_plugins[plugin_name] = Plugin(
                name=plugin_name,
                project_path=project_path,
                project_name=project_name,
                operator=loaded_entrypoint(*args) if invoke_on_load else loaded_entrypoint
            )
            LOG.info(f"PluginManager: Loaded {plugin_name} plugin from path - {project_path}")
        self._plugins.setdefault(ns, {}).update(loaded_plugins)
        return loaded_plugins

    def load_plugins(self, namespace, invoke_on_load=True, args=()):
        """
            Loads all plugins for a given namespace by discovering their entrypoints.

            :param namespace (str): The namespace from which to load plugins.
            :param invoke_on_load (bool): Whether to call the entrypoint immediately upon loading.
            :param args (tuple): Arguments to pass to the entrypoint if invoked.
            :return (dict): A dictionary mapping plugin names to plugin objects that were loaded.
        """

        entrypoints = metadata_importlib.entry_points()
        loaded_plugins = self._load_entrypoints(
            entrypoints=entrypoints.get(namespace, []),
            namespace=namespace,
            invoke_on_load=invoke_on_load,
            args=args
        )
        return loaded_plugins

    def load_plugins_from_path(self, plugin_path, invoke_on_load=True, args=()):
        """
            Loads all plugins from a specified filesystem path.
            Scans all distributions in the given path, collects their entrypoints grouped by
            namespace and loads them.

            :param plugin_path (str): Filesystem path containing plugin distributions.
            :param invoke_on_load (bool): Whether to call each entrypoint upon loading.
            :param args (tuple): Arguments to pass to entrypoints if invoked.
        """
        distributions = metadata_importlib.distributions(path=[plugin_path])
        for distribution in distributions:
            try:
                entrypoints_by_ns = {}
                for ep in distribution.entry_points:
                    entrypoints_by_ns.setdefault(ep.group, []).append(ep)

                for namespace, eps in entrypoints_by_ns.items():
                    self._load_entrypoints(
                        entrypoints=eps,
                        namespace=namespace,
                        invoke_on_load=invoke_on_load,
                        args=args
                    )
            except Exception as e:
                LOG.error(
                    f"PluginManager: Failed to load entrypoints from dist {distribution} - {e}"
                )
        LOG.info(f"PluginManager: Successfully loaded plugins from {plugin_path}")

    def discover_plugins(self, *args):
        """
            Discovers and loads plugins from predefined namespaces.
            Clears the internal plugin registry and loads plugins from standard namespaces such as
            helm applications, kustomize operators, and lifecycle operators.

            :param args: optional arguments to pass to each plugin upon loading.
        """
        self._plugins = {}
        self._subnamespace_plugins = {}
        namespaces = (
            PLUGIN_NS_HELM_APPLICATIONS,
            PLUGIN_NS_KUSTOMIZE_OPS,
            PLUGIN_NS_LIFECYCLE_OPS
        )
        for ns in namespaces:
            self.load_plugins(namespace=ns, args=args)

        LOG.info(
            f"PluginManager: Successfully loaded plugins from namespaces {', '.join(namespaces)}"
        )

    def activate_plugins(self, app_name, app_version, has_plugin_path, sync_plugins_dir, args=()):
        """
            Activates plugins for a specific application by enabling its plugin directory.
            For system applications, creates a .pth file pointing to the plugin directory, adds it
            to the python path and loads all plugins from the directory.

            :param app_name (str): Name of the application.
            :param app_version (str): Version of the application.
            :param has_plugin_path (bool): Indicates if the application already has a plugin path
                                      created.
            :param sync_plugins_dir (str): Path to the directory containing the plugins to
                                           activate.
            :param args (tuple): Arguments to pass to the plugins upon loading.
        """
        pth_fqpn = f"{APP_PLUGIN_PATH}/{APP_PTH_PREFIX}{app_name}-{app_version}.pth"

        if has_plugin_path and sync_plugins_dir in site.removeduppaths():
            return

        if not has_plugin_path and os.path.isfile(pth_fqpn):
            raise SysinvException((
                    "Error while activating plugins for {}. "
                    "File {} was found but the required plugin "
                    "directory {} does not exist."
                    .format(app_name, pth_fqpn, sync_plugins_dir)))
        elif has_plugin_path:
            if not os.path.isfile(pth_fqpn):
                try:
                    with open(pth_fqpn, 'w') as f:
                        f.write(sync_plugins_dir + '\n')
                        LOG.info(
                            f"PluginManager: Enabled plugin directory"
                            f"{sync_plugins_dir}: created {pth_fqpn}"
                        )
                except IOError as e:
                    raise SysinvException(
                        f"PluginManager: Failed to create the {app_name} plugin directory. \
                        Error: {e}"
                    )
            site.addsitedir(sync_plugins_dir)
            self.load_plugins_from_path(plugin_path=sync_plugins_dir, args=args)

    def deactivate_plugins(self, app_name, app_version, has_plugin_path, sync_plugins_dir):
        """
            Deactivates plugins for a specific system application and cleans up related resources.
            Removes the corresponding .pth file to prevent rediscovery on restart, unregisters the
            plugin directory from python’s import path, and clears loaded modules from the system
            cache. Also removes plugin references from the internal plugin registries.

            :param app_name (str): Name of the application whose plugins should be deactivated.
            :param app_version (str): Version of the application.
            :param has_plugin_path (bool): Indicates if the application already has a plugin path
                                      created.
            :param sync_plugins_dir (str): Filesystem path of the plugin directory to deactivate.
        """
        # If the application doesn't have any plugins, skip deactivation.
        if not has_plugin_path:
            return

        pth_fqpn = f"{APP_PLUGIN_PATH}/{APP_PTH_PREFIX}{app_name}-{app_version}.pth"

        try:
            # Remove the pth file, so on a conductor restart this installed plugin is not
            # discoverable.
            if os.path.exists(pth_fqpn):
                os.remove(pth_fqpn)
                LOG.info(
                    f"PluginManager: Disabled plugin directory {sync_plugins_dir}"
                    f"removed {pth_fqpn}"
                )
            sys.path.remove(sync_plugins_dir)
        except ValueError:
            pass
        except OSError as e:
            LOG.warning(
                f"PluginManager: Failed to remove plugin directory: {pth_fqpn}. Error: {e}"
            )
            pass

        # Remove modules whose source files or spec origins come from this plugin directory;
        # some modules lack __file__, so __spec__.origin is also checked for reliable cleanup.
        for modname in tuple(sys.modules.keys()):
            try:
                mod = sys.modules.get(modname)
                if not mod:
                    continue
                if (
                    hasattr(mod, "__file__") and
                    mod.__file__ and
                    sync_plugins_dir in os.path.realpath(mod.__file__)
                ):
                    del sys.modules[modname]
                    continue
                spec = getattr(mod, "__spec__", None)
                if spec and spec.origin and sync_plugins_dir in os.path.realpath(spec.origin):
                    del sys.modules[modname]
                    continue
            except Exception:
                pass

        # Removes the loaded plugins from plugin manager instance.
        plugins = self._get_plugins_by_project_path(sync_plugins_dir)
        for namespace, plugins_list in plugins.items():
            for plugin in plugins_list:
                self._plugins[namespace].pop(plugin.name)
                self._subnamespace_plugins.get(namespace, {}).pop(plugin.name, None)
        LOG.info(f"PluginManager: Successfully deactivate plugins from path {sync_plugins_dir}")

    @staticmethod
    def install_plugins(app_name, inst_plugins_dir, sync_plugins_dir):
        """
            Installs application plugins from wheel files into the synchronized plugin directory.
            Searches for all wheel files in the given installation directory, creates the target
            plugin directory if it does not exist, and extracts the contents of each wheel into it.

            :param app_name (str): Name of the application whose plugins are being installed.
            :param inst_plugins_dir (str): Path to the directory containing the plugin wheel files.
            :param sync_plugins_dir (str): Destination directory where the plugin files will be
                                           extracted.
        """
        # An app may be packaged with multiple wheels, discover and install them
        # in the synced app plugin directory
        pattern = '{}/*.whl'.format(inst_plugins_dir)
        discovered_whls = glob.glob(pattern)

        if not discovered_whls:
            LOG.info(f"PluginManager: {app_name} does not contains any platform plugins.")
            return

        if not os.path.isdir(sync_plugins_dir):
            try:
                LOG.info(
                    f"PluginManager: Creating {app_name} plugin directory {sync_plugins_dir}."
                )
                os.makedirs(sync_plugins_dir)
            except FileExistsError:
                LOG.warning(
                    f"PluginManager: The plugin directory {sync_plugins_dir} already exists."
                )
        for whl in discovered_whls:
            LOG.info(f"PluginManager: Installing {app_name} plugin {whl} to {sync_plugins_dir}.")
            try:
                with zipfile.ZipFile(whl) as zf:
                    zf.extractall(sync_plugins_dir)
            except Exception as e:
                LOG.error(
                    f"PluginManager: The {whl} extraction from {app_name} failed with error: {e}"
                )
                continue

    @staticmethod
    def uninstall_plugins(sync_plugins_dir):
        """
            Uninstalls application plugins by removing the specified plugin directory.
            Deletes the entire plugin directory and its contents.

            :param sync_plugins_dir (str): Filesystem path of the plugin directory to remove.
        """
        if os.path.isdir(sync_plugins_dir):
            try:
                LOG.info(f"PluginManager: Removing plugin directory {sync_plugins_dir}")
                shutil.rmtree(sync_plugins_dir)
            except OSError:
                LOG.exception(
                    f"PluginManager: Failed to remove plugin directory: {sync_plugins_dir}"
                )
        else:
            LOG.info(f"PluginManager: Plugin directory {sync_plugins_dir} does not exist. No "
                     "need to remove.")

    def get_plugins_by_namespace(self, namespace):
        return self._plugins.get(namespace, {})

    def get_plugin(self, namespace, plugin_name, fallback_to_generic=True):
        """
            Retrieves a specific plugin by name within a given namespace.
            If the requested plugin is not found and `fallback_to_generic` is True, the method
            returns the generic plugin for that namespace instead.

            :param namespace (str): The namespace from which to retrieve the plugin.
            :param plugin_name (str): The name of the plugin to retrieve.
            :param fallback_to_generic (bool): Whether to return the generic plugin if the
                                               specified one is not found.
            :return (Plugin): The requested Plugin object, or the generic plugin if fallback is
                              enabled.
        """
        plugin = self._plugins[namespace].get(plugin_name)

        if not plugin and fallback_to_generic:
            LOG.info(
                f"PluginManager: {plugin_name} not found in namespace {namespace}. "
                "Returning generic plugin."
            )
            plugin = self._plugins[namespace]['generic']
        return plugin

    def get_subnamespace_plugins(self, namespace):
        return self._subnamespace_plugins.get(namespace, {})

    def get_subnamespace_relation_by_plugin_name(self, namespace, plugin_name):
        return self._subnamespace_plugins.get(namespace, {}).get(plugin_name, [])

    def audit_plugins(self, dbapi):
        """
            Audits installed plugins to ensure that only enabled and valid application plugins are
            discoverable. Scans all existing .pth files under the application plugin path and
            verifies that each one corresponds to an active and correctly versioned application.

            :param dbapi: Database API interface.
        """

        # An enabled plugin will have a python path configuration file name with the
        # following format: stx_app-platform-integ-apps-1.0-8.pth
        PTH_PATTERN = re.compile(
            f"{HELM_OVERRIDES_PATH}/([\w-]+)/(\d+\.\d+-\d+.*)/plugins")

        pattern = f"{APP_PLUGIN_PATH}/{APP_PTH_PREFIX}*.pth"
        discoverable_pths = glob.glob(pattern)
        LOG.debug(f"PluginManager: Discoverable app plugins: {discoverable_pths}")

        # Examine existing pth files to make sure they are still valid
        for pth in discoverable_pths:
            with open(pth, 'r') as f:
                contents = f.readlines()

            if len(contents) == 1:
                plugin_folder = contents[0].strip('\n')
                LOG.debug(f"PluginManager: Plugin Path: {plugin_folder}")
                match = PTH_PATTERN.match(plugin_folder)
                if match:
                    app = match.group(1)
                    ver = match.group(2)
                    try:
                        app_obj = dbapi.kube_app_get(app)
                        if app_obj.app_version == ver:
                            LOG.info(f"PluginManager: App {app}, version {ver}: Found "
                                     "valid plugin")
                            continue
                        else:
                            LOG.warning("PluginManager: Stale plugin pth file "
                                        f"found {pth}: Wrong plugin version "
                                        f"enabled {ver} != {app_obj.app_version}")
                    except KubeAppNotFound:
                        LOG.warning("PluginManager: Stale plugin pth file found "
                                    f"{pth}: App is not active.")
                else:
                    LOG.warning(f"PluginManager: Invalid pth file {pth}: Invalid "
                                "name or version.")

                # Remove plugin folder from sys.path
                try:
                    sys.path.remove(plugin_folder)
                except ValueError:
                    LOG.warning(f"Failed to remove directory {plugin_folder} from sys.path "
                                f"while evaluating invalid plugin .pth file {pth}.")
            else:
                LOG.warning(f"PluginManager: Invalid pth file {pth}: Only one path "
                            "is expected.")

            try:
                LOG.info(f"PluginManager: Removing invalid plugin pth: {pth}")
                os.remove(pth)
            except ValueError:
                LOG.error(f"PluginManager: Failed to remove invalid plugin pth: {pth}.")

    def list_plugins(self):
        loaded_plugins = []
        for ns, plugins in self._plugins.items():
            for plugin in plugins.values():
                loaded_plugins.append(
                    {
                        'name': plugin.name,
                        'project_name': plugin.project_name,
                        'project_path': plugin.project_path,
                        'namespace': ns
                    }
                )
        return loaded_plugins
