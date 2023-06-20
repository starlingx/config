#
# Copyright (c) 2018-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

""" System Inventory Helm Overrides Operator."""

from __future__ import absolute_import

import eventlet
import os
import tempfile
import yaml

from six import iteritems
from stevedore import extension

from oslo_log import log as logging
from sysinv.common import exception
from sysinv.common import utils
from sysinv.helm import common
from sysinv.helm import utils as helm_utils


LOG = logging.getLogger(__name__)

# Disable yaml feature 'alias' for clean and readable output
yaml.Dumper.ignore_aliases = lambda *data: True

# Number of characters to strip off from helm plugin name defined in setup.cfg,
# in order to allow controlling the order of the helm plugins, without changing
# the names of the plugins.
# The convention here is for the helm plugins to be named ###_PLUGINNAME.
HELM_PLUGIN_PREFIX_LENGTH = 4

# Number of optional characters appended to FluxCD kustomize operator name, to
# allow overriding with a newer version of the FluxCD kustomize operator. The
# convention here is for the FluxCD kustomize operator plugins to allow an
# optional suffix, as in PLUGINNAME_###.
FLUXCD_PLUGIN_SUFFIX_LENGTH = 4

# Number of optional characters appended to AppLifecycle operator name,
# to allow overriding with a newer version of the AppLifecycle operator.
# The convention here is for the AppLifecycle operator plugins to allow an
# optional suffix, as in PLUGINNAME_###.
LIFECYCLE_PLUGIN_SUFFIX_LENGTH = 4


def helm_context(func):
    """Decorate to initialize the local threading context"""

    def _wrapper(self, *args, **kwargs):
        thread_context = eventlet.greenthread.getcurrent()
        setattr(thread_context, '_helm_context', dict())
        return func(self, *args, **kwargs)
    return _wrapper


def suppress_stevedore_errors(manager, entrypoint, exception):
    """
    stevedore.ExtensionManager will try to import the entry point defined in the module.
    For helm_applications, both stx_openstack and platform_integ_apps are virtual modules.
    So ExtensionManager will throw the "Could not load ..." error message, which is expected.
    Just suppress this error message to avoid cause confusion.
    """
    pass


LOCK_NAME = 'HelmOperator'


class HelmOperator(object):
    """Class to encapsulate helm override operations for System Inventory"""

    # Define the stevedore namespaces that will need to be managed for plugins
    STEVEDORE_APPS = 'systemconfig.helm_applications'
    STEVEDORE_FLUXCD = 'systemconfig.fluxcd.kustomize_ops'
    STEVEDORE_LIFECYCLE = 'systemconfig.app_lifecycle'

    def __init__(self, dbapi=None):
        self.dbapi = dbapi

        # Find all plugins for apps, charts per app, and fluxcd operators
        self.discover_plugins()

    @utils.synchronized(LOCK_NAME)
    def discover_plugins(self):
        """ Scan for all available plugins """

        LOG.debug("HelmOperator: Loading available helm, fluxcd and lifecycle plugins.")

        # Initialize the plugins
        self.helm_system_applications = {}
        self.chart_operators = {}
        self.fluxcd_kustomize_operators = {}
        self.app_lifecycle_operators = {}

        # Need to purge the stevedore plugin cache so that when we discover the
        # plugins, new plugin resources are found. If the cache exists, then no
        # new plugins are discoverable.
        self.purge_cache()

        # dict containing sequence of helm charts per app
        self.helm_system_applications = self._load_helm_applications()

        # dict containing FluxCD kustomize operators per app
        self.fluxcd_kustomize_operators = self._load_fluxcd_kustomize_operators()

        # dict containing app lifecycle operators per app
        self.app_lifecycle_operators = self._load_app_lifecycle_operators()

    @utils.synchronized(LOCK_NAME)
    def purge_cache_by_location(self, install_location):
        """Purge the stevedore entry point cache."""
        for lifecycle_ep in extension.ExtensionManager.ENTRY_POINT_CACHE[self.STEVEDORE_LIFECYCLE]:
            lifecycle_distribution = None

            try:
                lifecycle_distribution = utils.get_distribution_from_entry_point(lifecycle_ep)
                (project_name, project_location) = \
                    utils.get_project_name_and_location_from_distribution(lifecycle_distribution)

                if project_location == install_location:
                    extension.ExtensionManager.ENTRY_POINT_CACHE[self.STEVEDORE_LIFECYCLE].remove(lifecycle_ep)
                    break
            except Exception as e:
                LOG.error("Error while trying to purge lifecycle entry point {}, error: {}".
                          format(lifecycle_ep, e))

                # Temporary suppress errors on Debian until Stevedore is reworked.
                # See https://storyboard.openstack.org/#!/story/2009101
                if utils.is_debian():
                    LOG.info("Deleting {} from cache".format(lifecycle_ep))
                    try:
                        extension.ExtensionManager.ENTRY_POINT_CACHE[self.STEVEDORE_LIFECYCLE].remove(lifecycle_ep)
                    except Exception as e:
                        LOG.error("Tried removing lifecycle_ep {}, error: {}".format(lifecycle_ep, e))
                else:
                    raise
        else:
            LOG.info("Couldn't find endpoint distribution located at %s for "
                     "%s" % (install_location, lifecycle_distribution))

        for fluxcd_ep in extension.ExtensionManager.ENTRY_POINT_CACHE[self.STEVEDORE_FLUXCD]:
            fluxcd_distribution = None

            try:
                fluxcd_distribution = utils.get_distribution_from_entry_point(fluxcd_ep)
                (project_name, project_location) = \
                    utils.get_project_name_and_location_from_distribution(fluxcd_distribution)

                if project_location == install_location:
                    extension.ExtensionManager.ENTRY_POINT_CACHE[self.STEVEDORE_FLUXCD].remove(fluxcd_ep)
                    break
            except Exception as e:
                LOG.error("Error while trying to purge flux entry point {}, error: {}".
                          format(fluxcd_ep, e))

                # Temporary suppress errors on Debian until Stevedore is reworked.
                # See https://storyboard.openstack.org/#!/story/2009101
                if utils.is_debian():
                    LOG.info("Deleting {} from cache".format(fluxcd_ep))
                    try:
                        extension.ExtensionManager.ENTRY_POINT_CACHE[self.STEVEDORE_FLUXCD].remove(fluxcd_ep)
                    except Exception as e:
                        LOG.error("Tried removing fluxcd_ep {}, error: {}".format(fluxcd_ep, e))
                else:
                    raise
        else:
            LOG.info("Couldn't find endpoint distribution located at %s for "
                     "%s" % (install_location, fluxcd_distribution))

        for app_ep in extension.ExtensionManager.ENTRY_POINT_CACHE[self.STEVEDORE_APPS]:
            try:
                if utils.is_debian():
                    if app_ep.name in install_location:
                        namespace = app_ep.value
                        purged_list = []
                        for helm_ep in extension.ExtensionManager.ENTRY_POINT_CACHE[namespace]:
                            helm_distribution = utils.get_distribution_from_entry_point(helm_ep)
                            (helm_project_name, helm_project_location) = \
                                utils.get_project_name_and_location_from_distribution(helm_distribution)

                            if helm_project_location != install_location:
                                purged_list.append(helm_ep)

                        if purged_list:
                            extension.ExtensionManager.ENTRY_POINT_CACHE[namespace] = purged_list
                        else:
                            del extension.ExtensionManager.ENTRY_POINT_CACHE[namespace]
                            extension.ExtensionManager.ENTRY_POINT_CACHE[self.STEVEDORE_APPS].remove(app_ep)
                            LOG.info("Removed stevedore namespace: %s" % namespace)
                else:
                    app_distribution = utils.get_distribution_from_entry_point(app_ep)
                    (app_project_name, app_project_location) = \
                        utils.get_project_name_and_location_from_distribution(app_distribution)

                    if app_project_location == install_location:
                        namespace = utils.get_module_name_from_entry_point(app_ep)

                        purged_list = []
                        for helm_ep in extension.ExtensionManager.ENTRY_POINT_CACHE[namespace]:
                            helm_distribution = utils.get_distribution_from_entry_point(helm_ep)
                            (helm_project_name, helm_project_location) = \
                                utils.get_project_name_and_location_from_distribution(helm_distribution)

                            if helm_project_location != install_location:
                                purged_list.append(helm_ep)

                        if purged_list:
                            extension.ExtensionManager.ENTRY_POINT_CACHE[namespace] = purged_list
                        else:
                            del extension.ExtensionManager.ENTRY_POINT_CACHE[namespace]
                            extension.ExtensionManager.ENTRY_POINT_CACHE[self.STEVEDORE_APPS].remove(app_ep)
                            LOG.info("Removed stevedore namespace: %s" % namespace)
            except Exception as e:
                # Temporary suppress errors on Debian until Stevedore is reworked.
                # See https://storyboard.openstack.org/#!/story/2009101
                if utils.is_debian():
                    LOG.info("Tried removing app_ep {}, error: {}".format(app_ep, e))
                    continue
                else:
                    raise

    def purge_cache(self):
        """Purge the stevedore entry point cache."""
        if self.STEVEDORE_APPS in extension.ExtensionManager.ENTRY_POINT_CACHE:
            for entry_point in extension.ExtensionManager.ENTRY_POINT_CACHE[self.STEVEDORE_APPS]:
                namespace = utils.get_module_name_from_entry_point(entry_point)
                try:
                    del extension.ExtensionManager.ENTRY_POINT_CACHE[namespace]
                    LOG.debug("Deleted entry points for %s." % namespace)
                except KeyError:
                    LOG.info("No entry points for %s found." % namespace)

            try:
                del extension.ExtensionManager.ENTRY_POINT_CACHE[self.STEVEDORE_APPS]
                LOG.debug("Deleted entry points for %s." % self.STEVEDORE_APPS)
            except KeyError:
                LOG.info("No entry points for %s found." % self.STEVEDORE_APPS)

        else:
            LOG.info("No entry points for %s found." % self.STEVEDORE_APPS)

        try:
            del extension.ExtensionManager.ENTRY_POINT_CACHE[self.STEVEDORE_FLUXCD]
            LOG.debug("Deleted entry points for %s." % self.STEVEDORE_FLUXCD)
        except KeyError:
            LOG.info("No entry points for %s found." % self.STEVEDORE_FLUXCD)

        try:
            del extension.ExtensionManager.ENTRY_POINT_CACHE[self.STEVEDORE_LIFECYCLE]
            LOG.debug("Deleted entry points for %s." % self.STEVEDORE_LIFECYCLE)
        except KeyError:
            LOG.info("No entry points for %s found." % self.STEVEDORE_LIFECYCLE)

    def _load_app_lifecycle_operators(self):
        """Build a dictionary of AppLifecycle operators"""

        operators_dict = {}

        app_lifecycle_operators = extension.ExtensionManager(
            namespace=self.STEVEDORE_LIFECYCLE,
            invoke_on_load=True, invoke_args=())

        sorted_app_lifecycle_operators = sorted(
            app_lifecycle_operators.extensions, key=lambda x: x.name)

        for operator in sorted_app_lifecycle_operators:
            if (operator.name[-(LIFECYCLE_PLUGIN_SUFFIX_LENGTH - 1):].isdigit() and
                    operator.name[-LIFECYCLE_PLUGIN_SUFFIX_LENGTH:-3] == '_'):
                operator_name = operator.name[0:-LIFECYCLE_PLUGIN_SUFFIX_LENGTH]
            else:
                operator_name = operator.name
            operators_dict[operator_name] = operator.obj

        return operators_dict

    def get_app_lifecycle_operator(self, app_name):
        """Return an AppLifecycle operator based on app name"""

        plugin_name = utils.find_app_plugin_name(app_name)
        if plugin_name in self.app_lifecycle_operators:
            operator = self.app_lifecycle_operators[plugin_name]
        else:
            operator = self.app_lifecycle_operators['generic']

        return operator

    def _load_fluxcd_kustomize_operators(self):
        """Build a dictionary of FluxCD kustomize operators"""

        operators_dict = {}
        dist_info_dict = {}

        fluxcd_kustomize_operators = extension.ExtensionManager(
            namespace=self.STEVEDORE_FLUXCD,
            invoke_on_load=True, invoke_args=())

        sorted_fluxcd_kustomize_operators = sorted(
            fluxcd_kustomize_operators.extensions, key=lambda x: x.name)

        for op in sorted_fluxcd_kustomize_operators:
            if (op.name[-(FLUXCD_PLUGIN_SUFFIX_LENGTH - 1):].isdigit() and
                    op.name[-FLUXCD_PLUGIN_SUFFIX_LENGTH:-3] == '_'):
                op_name = op.name[0:-FLUXCD_PLUGIN_SUFFIX_LENGTH]
            else:
                op_name = op.name
            operators_dict[op_name] = op.obj

            distribution = utils.get_distribution_from_entry_point(op.entry_point)
            (project_name, project_location) = \
                utils.get_project_name_and_location_from_distribution(distribution)

            # Extract distribution information for logging
            dist_info_dict[op_name] = {
                'name': project_name,
                'location': project_location,
            }

        # Provide some log feedback on plugins being used
        for (app_name, info) in iteritems(dist_info_dict):
            LOG.info("Plugins for %-20s: loaded from %-20s - %s." % (app_name,
                info['name'], info['location']))

        return operators_dict

    def get_fluxcd_kustomize_operator(self, app_name):
        """Return a kustomize operator based on app name"""

        plugin_name = utils.find_app_plugin_name(app_name)
        if plugin_name in self.fluxcd_kustomize_operators:
            kustomize_op = self.fluxcd_kustomize_operators[plugin_name]
        else:
            kustomize_op = self.fluxcd_kustomize_operators['generic']
        return kustomize_op

    def _load_helm_applications(self):
        """Build a dictionary of supported helm applications"""

        helm_application_dict = {}
        helm_applications = extension.ExtensionManager(
            namespace=self.STEVEDORE_APPS,
            on_load_failure_callback=suppress_stevedore_errors
        )
        for entry_point in helm_applications.list_entry_points():
            helm_application_dict[entry_point.name] = \
                utils.get_module_name_from_entry_point(entry_point)

        supported_helm_applications = {}
        for name, namespace in helm_application_dict.items():
            supported_helm_applications[name] = []
            helm_plugins = extension.ExtensionManager(
                namespace=namespace, invoke_on_load=True, invoke_args=(self,))
            sorted_helm_plugins = sorted(helm_plugins.extensions, key=lambda x: x.name)
            for plugin in sorted_helm_plugins:
                distribution = utils.get_distribution_from_entry_point(plugin.entry_point)
                (project_name, project_location) = \
                    utils.get_project_name_and_location_from_distribution(distribution)

                LOG.debug("%s: helm plugin %s loaded from %s - %s." % (name,
                    plugin.name,
                    project_name,
                    project_location))

                plugin_name = plugin.name[HELM_PLUGIN_PREFIX_LENGTH:]
                self.chart_operators.update({plugin_name: plugin.obj})
                # Remove duplicates, keeping last occurrence only
                if plugin_name in supported_helm_applications[name]:
                    supported_helm_applications[name].remove(plugin_name)
                supported_helm_applications[name].append(plugin_name)

        return supported_helm_applications

    def get_active_helm_applications(self):
        """ Get the active system applications and charts """
        return self.helm_system_applications

    @property
    def context(self):
        thread_context = eventlet.greenthread.getcurrent()
        return getattr(thread_context, '_helm_context')

    def get_helm_chart_namespaces_by_app(self, chart_name, app_name):
        """Get supported chart namespaces for a given application.

        This method retrieves the namespace supported by a given chart.

        :param chart_name: name of the chart
        :param app_name: name of the application
        :returns: list of supported namespaces that associated overrides may be
                  provided.
        """

        namespaces = []
        if chart_name in self.chart_operators:
            app_plugin_name = utils.find_app_plugin_name(app_name)

            namespaces = self.chart_operators[chart_name].get_namespaces_by_app(
                app_plugin_name)
        return namespaces

    def get_helm_chart_namespaces(self, chart_name):
        """Get supported chart namespaces.

        This method retrieves the namespace supported by a given chart.

        :param chart_name: name of the chart
        :returns: list of supported namespaces that associated overrides may be
                  provided.
        """

        namespaces = []
        if chart_name in self.chart_operators:
            namespaces = self.chart_operators[chart_name].SUPPORTED_NAMESPACES
        return namespaces

    @helm_context
    def get_helm_chart_overrides(self, chart_name, cnamespace=None):
        """ RPCApi: Gets the *chart* overrides for a supported chart. """
        return self._get_helm_chart_overrides(chart_name, cnamespace)

    def _get_helm_chart_overrides(self, chart_name, cnamespace=None):
        """Get the overrides for a supported chart.

        This method retrieves overrides for a supported chart. Overrides for
        all supported namespaces will be returned unless a specific namespace
        is requested.

        :param chart_name: name of a supported chart
        :param cnamespace: (optional) namespace
        :returns: dict of overrides.

        Example Without a cnamespace parameter:
        {
            'kube-system': {
                'deployment': {
                    'mode': 'cluster',
                    'type': 'DaemonSet'
                },
            },
            'openstack': {
                'pod': {
                    'replicas': {
                        'server': 1
                    }
                }
            }
        }

        Example with a cnamespace parameter: cnamespace='kube-system'
        {
            'deployment': {
                'mode': 'cluster',
                'type': 'DaemonSet'
            }
        }
        """
        overrides = {}
        if chart_name in self.chart_operators:
            try:
                overrides.update(
                    self.chart_operators[chart_name].get_overrides(
                        cnamespace))
            except exception.InvalidHelmNamespace:
                raise
        return overrides

    def get_helm_application_namespaces(self, app_name):
        """Get supported application namespaces.

        This method retrieves a dict of charts and their supported namespaces
        for an application.

        :param app_name: name of the bundle of charts required to support an
                         application
        :returns: dict of charts and supported namespaces that associated
                  overrides may be provided.
        """

        app, plugin_name = self._find_kube_app_and_app_plugin_name(app_name)

        app_namespaces = {}
        if plugin_name in self.helm_system_applications:
            for chart_name in self.helm_system_applications[plugin_name]:
                try:
                    app_namespaces.update(
                        {chart_name:
                         self.get_helm_chart_namespaces_by_app(
                             chart_name, app_name)})
                except exception.InvalidHelmNamespace as e:
                    LOG.info(e)
        else:
            # Generic apps
            db_namespaces = self.dbapi.helm_override_get_all(app.id)
            for chart in db_namespaces:
                app_namespaces.setdefault(
                    chart.name, []).append(chart.namespace)

        return app_namespaces

    @helm_context
    def get_helm_application_overrides(self, app_name, cnamespace=None):
        """RPCApi: Gets the application overrides for a supported set of charts."""
        return self._get_helm_application_overrides(app_name, cnamespace)

    def _get_helm_application_overrides(self, app_name, cnamespace=None):
        """Get the overrides for a supported set of charts.

        This method retrieves overrides for a set of supported charts that
        comprise an application. Overrides for all charts and all supported
        namespaces will be returned unless a specific namespace is requested.

        If a specific namespace is requested, then only charts that support
        that specified namespace will be returned.

        :param app_name: name of a supported application (set of charts)
        :param cnamespace: (optional) namespace
        :returns: dict of overrides.

        Example:
        {
            'ingress': {
                'kube-system': {
                    'deployment': {
                        'mode': 'cluster',
                        'type': 'DaemonSet'
                    },
                },
                'openstack': {
                    'pod': {
                        'replicas': {
                            'server': 1
                        }
                    }
                }
            },
            'glance': {
                'openstack': {
                    'pod': {
                        'replicas': {
                            'server': 1
                        }
                    }
                }
             }
        }
        """
        overrides = {}
        plugin_name = utils.find_app_plugin_name(app_name)

        if plugin_name in self.helm_system_applications:
            for chart_name in self.helm_system_applications[plugin_name]:
                try:
                    overrides.update({chart_name:
                                      self._get_helm_chart_overrides(
                                          chart_name,
                                          cnamespace)})
                except exception.InvalidHelmNamespace as e:
                    LOG.info(e)
        return overrides

    def merge_overrides(self, file_overrides=None, set_overrides=None):
        """ Merge helm overrides together.

        :param values: A dict of different types of user override values,
                       'files' (which generally specify many overrides) and
                       'set' (which generally specify one override).
        """

        if file_overrides is None:
            file_overrides = []
        if set_overrides is None:
            set_overrides = []
        # At this point we have potentially two separate types of overrides
        # specified by system or user, values from files and values passed in
        # via --set .  We need to ensure that we call helm using the same
        # mechanisms to ensure the same behaviour.
        args = []

        # Process the newly-passed-in override values
        tmpfiles = []

        for value_file in file_overrides:
            # For values passed in from files, write them back out to
            # temporary files.
            tmpfile = tempfile.NamedTemporaryFile(delete=False)
            tmpfile.write(value_file.encode() if type(value_file) == str else value_file)
            tmpfile.close()
            tmpfiles.append(tmpfile.name)
            args.extend(['--values', tmpfile.name])

        for value_set in set_overrides:
            keypair = list(value_set.split("="))

            # request user to input with "--set key=value" or
            # "--set key=", for the second case, the value is assume ""
            # skip setting like "--set =value", "--set xxxx"
            if len(keypair) == 2 and keypair[0]:
                if keypair[1] and keypair[1].isdigit():
                    args.extend(['--set-string', value_set])
                else:
                    args.extend(['--set', value_set])

        try:
            # Apply changes by calling out to helm to do values merge
            # using a dummy chart.
            output = helm_utils.install_helm_chart_with_dry_run(args)
            # Extract the info we want.
            values = output.split('USER-SUPPLIED VALUES:\n')[1].split(
                '\nCOMPUTED VALUES:')[0]
        except Exception as e:
            LOG.error("Failed to merge overrides %s" % e)
            raise

        for tmpfile in tmpfiles:
            os.remove(tmpfile)

        return values

    @helm_context
    def generate_helm_chart_overrides(self, path, chart_name, cnamespace=None):
        """Generate system helm chart overrides

        This method will generate system helm chart override an write them to a
        yaml file for use with the helm command. If the namespace is provided
        only the overrides file for that specified namespace will be written.

        :param chart_name: name of a supported chart
        :param cnamespace: (optional) namespace
        """

        if chart_name in self.chart_operators:
            namespaces = self.chart_operators[chart_name].SUPPORTED_NAMESPACES
            if cnamespace and cnamespace not in namespaces:
                LOG.exception("The %s chart does not support namespace: %s" %
                              (chart_name, cnamespace))
                return

            try:
                overrides = self._get_helm_chart_overrides(
                    chart_name,
                    cnamespace)
                self._write_chart_overrides(path,
                                            chart_name,
                                            cnamespace,
                                            overrides)
            except Exception as e:
                LOG.exception("failed to create chart overrides for %s: %s" %
                              (chart_name, e))
        elif chart_name:
            LOG.exception("%s chart is not supported" % chart_name)
        else:
            LOG.exception("chart name is required")

    @helm_context
    @utils.synchronized(LOCK_NAME)
    def generate_helm_application_overrides(self, path, app_name,
                                                    mode=None,
                                                    cnamespace=None,
                                                    chart_info=None,
                                                    combined=False):
        """Create the system overrides files for a supported application

        This method will generate system helm chart overrides yaml files for a
        set of supported charts that comprise an application. If the namespace
        is provided only the overrides files for that specified namespace will
        be written.

        :param app_name: name of the bundle of charts required to support an
            application
        :param mode: mode to control how to apply application manifest
        :param cnamespace: (optional) namespace
        :param chart_info: (optional) supporting chart information
            extracted from the fluxcd manifests which is used to influence
            overrides
        :param combined: (optional) whether to apply user overrides on top of
            system overrides
        """

        app, plugin_name = self._find_kube_app_and_app_plugin_name(app_name)

        # Get a kustomize operator to provide a single point of
        # manipulation for the chart resources
        kustomize_op = self.get_fluxcd_kustomize_operator(app.name)

        # Load the FluxCD manifests into the operator
        fluxcd_manifests_dir = utils.generate_synced_fluxcd_manifests_fqpn(
            app.name, app.app_version)
        kustomize_op.load(fluxcd_manifests_dir)

        if plugin_name in self.helm_system_applications:
            app_overrides = self._get_helm_application_overrides(plugin_name,
                                                                 cnamespace)
            for (chart_name, overrides) in iteritems(app_overrides):
                if combined:
                    # The overrides at this point are the system overrides. For
                    # charts with multiple namespaces, the overrides would
                    # contain multiple keys, one for each namespace.
                    #
                    # Retrieve the user overrides of each namespace from the
                    # database and merge this list of user overrides, if they
                    # exist, with the system overrides. Both system and user
                    # override contents are then merged based on the namespace,
                    # prepended with required header and written to
                    # corresponding files (<namespace>-<chart>.yaml).
                    file_overrides = []
                    for chart_namespace in overrides.keys():
                        try:
                            db_chart = self.dbapi.helm_override_get(
                                app.id, chart_name, chart_namespace)
                            db_user_overrides = db_chart.user_overrides
                            if db_user_overrides:
                                file_overrides.append(
                                    yaml.dump(
                                        {chart_namespace: yaml.load(
                                            db_user_overrides,
                                            Loader=yaml.FullLoader
                                        )}
                                    )
                                )
                        except exception.HelmOverrideNotFound:
                            pass

                    if file_overrides:
                        # Use dump() instead of safe_dump() as the latter is
                        # not agreeable with password regex in some overrides
                        system_overrides = yaml.dump(overrides)
                        file_overrides.insert(0, system_overrides)
                        combined_overrides = self.merge_overrides(
                            file_overrides=file_overrides)
                        overrides = yaml.load(
                            combined_overrides,
                            Loader=yaml.FullLoader
                        )

                self._write_chart_overrides(path, chart_name, cnamespace, overrides)

                # Update manifest docs based on the plugin directives. If the
                # application does not provide a manifest operator, the
                # GenericFluxCDKustomizeOperator is used and chart specific
                # operations can be skipped.
                if kustomize_op.APP:
                    if chart_name in self.chart_operators:
                        self.chart_operators[chart_name].execute_kustomize_updates(
                            kustomize_op)

            # Update the kustomization manifests based on platform conditions
            kustomize_op.platform_mode_kustomize_updates(self.dbapi, mode)

        else:
            # Generic applications
            for chart in chart_info:
                try:
                    db_chart = self.dbapi.helm_override_get(
                        app.id, chart.name, chart.namespace)
                except exception.HelmOverrideNotFound:
                    # This routine is to create helm overrides entries
                    # in database during application-upload so that user
                    # can list the supported helm chart overrides of the
                    # application via helm-override-list
                    try:
                        values = {
                            'name': chart.name,
                            'namespace': chart.namespace,
                            'app_id': app.id,
                        }
                        db_chart = self.dbapi.helm_override_create(values=values)
                    except Exception as e:
                        LOG.exception(e)
                        return

                user_overrides = {chart.namespace: {}}
                db_user_overrides = db_chart.user_overrides
                if db_user_overrides:
                    user_overrides = yaml.load(
                        yaml.dump(
                            {chart.namespace: yaml.load(
                                db_user_overrides,
                                Loader=yaml.FullLoader
                            )}),
                        Loader=yaml.FullLoader
                    )

                self._write_chart_overrides(path, chart.name,
                                            cnamespace, user_overrides)

        # Write the kustomization doc overrides and a unified manifest for deletion.
        kustomize_op.save_kustomization_updates()
        kustomize_op.save_release_cleanup_data()

    def _find_kube_app_and_app_plugin_name(self, app_name):
        return utils.find_kube_app(self.dbapi, app_name), \
               utils.find_app_plugin_name(app_name)

    def remove_helm_chart_overrides(self, path, chart_name, cnamespace=None):
        """Remove the overrides files for a chart"""

        if chart_name in self.chart_operators:
            namespaces = self.chart_operators[chart_name].SUPPORTED_NAMESPACES

            filenames = []
            if cnamespace and cnamespace in namespaces:
                filenames.append("%s-%s.yaml" % (cnamespace, chart_name))
            else:
                for n in namespaces:
                    filenames.append("%s-%s.yaml" % (n, chart_name))

            for f in filenames:
                try:
                    self._remove_overrides(path, f)
                except Exception as e:
                    LOG.exception("failed to remove %s overrides: %s: %s" % (
                        chart_name, f, e))
        else:
            LOG.exception("chart %s not supported for system overrides" %
                          chart_name)

    def _write_chart_overrides(self, path, chart_name, cnamespace, overrides):
        """Write a one or more overrides files for a chart. """

        def _write_file(filename, values):
            try:
                self._write_overrides(path, filename, values)
            except Exception as e:
                LOG.exception("failed to write %s overrides: %s: %s" % (
                    chart_name, filename, e))

        if cnamespace:
            _write_file("%s-%s.yaml" % (cnamespace, chart_name), overrides)
        else:
            for ns in overrides.keys():
                _write_file("%s-%s.yaml" % (ns, chart_name), overrides[ns])

    def _write_overrides(self, path, filename, overrides):
        """Write a single overrides file. """

        if not os.path.isdir(path):
            os.makedirs(path)

        filepath = os.path.join(path, filename)
        try:
            fd, tmppath = tempfile.mkstemp(dir=path, prefix=filename,
                                           text=True)

            with open(tmppath, 'w') as f:
                yaml.dump(overrides, f, default_flow_style=False)
            os.close(fd)
            os.rename(tmppath, filepath)
            # Change the permission to be readable to non-root users
            os.chmod(filepath, 0o644)
        except Exception:
            LOG.exception("failed to write overrides file: %s" % filepath)
            raise

    def _remove_overrides(self, path, filename):
        """Remove a single overrides file. """

        filepath = os.path.join(path, filename)
        try:
            if os.path.exists(filepath):
                os.unlink(filepath)
        except Exception:
            LOG.exception("failed to delete overrides file: %s" % filepath)
            raise

    @helm_context
    def version_check(self, app_name, app_version):
        """Validate application version"""
        if app_name in self.helm_system_applications:
            for chart_name in self.helm_system_applications[app_name]:
                if not self.chart_operators[chart_name].version_check(app_version):
                    LOG.info("Unsupported version reported by %s: %s %s" % (
                             chart_name, app_name, app_version))
                    return False

        # Return True by default
        return True


class HelmOperatorData(HelmOperator):
    """Class to allow retrieval of helm managed data"""

    # TODO (rchurch): decouple. Plugin chart names. This class needs to be
    # delivered as a plugin.
    HELM_CHART_KEYSTONE = 'keystone'
    HELM_CHART_NOVA = 'nova'
    HELM_CHART_CINDER = 'cinder'
    HELM_CHART_GLANCE = 'glance'
    HELM_CHART_NEUTRON = 'neutron'
    HELM_CHART_HEAT = 'heat'
    HELM_CHART_CEILOMETER = 'ceilometer'
    HELM_CHART_DCDBSYNC = 'dcdbsync'

    @helm_context
    def get_keystone_auth_data(self):
        keystone_operator = self.chart_operators[self.HELM_CHART_KEYSTONE]

        # use stx_admin account to communicate with openstack app
        username = common.USER_STX_ADMIN
        try:
            password = keystone_operator.get_stx_admin_password()
        except Exception:
            # old version app doesn't support stx_admin account yet.
            # fallback to admin account
            username = keystone_operator.get_admin_user_name()
            password = keystone_operator.get_admin_password()

        auth_data = {
            'admin_user_name':
                username,
            'admin_project_name':
                keystone_operator.get_admin_project_name(),
            'auth_host':
                'keystone.openstack.svc.cluster.local',
            'auth_port': 80,
            'admin_user_domain':
                keystone_operator.get_admin_user_domain(),
            'admin_project_domain':
                keystone_operator.get_admin_project_domain(),
            'admin_password':
                password,
        }
        return auth_data

    @helm_context
    def get_keystone_endpoint_data(self):
        keystone_operator = self.chart_operators[self.HELM_CHART_KEYSTONE]
        endpoint_data = {
            'endpoint_override':
                'http://keystone.openstack.svc.cluster.local:80',
            'region_name':
                keystone_operator.get_region_name(),
        }
        return endpoint_data

    @helm_context
    def get_keystone_oslo_db_data(self):
        keystone_operator = self.chart_operators[self.HELM_CHART_KEYSTONE]
        endpoints_overrides = keystone_operator.\
            _get_endpoints_oslo_db_overrides(self.HELM_CHART_KEYSTONE,
                                             ['keystone'])

        password = endpoints_overrides['keystone']['password']
        connection = "mysql+pymysql://keystone:%s@" \
                     "mariadb.openstack.svc.cluster.local:3306/keystone"\
                     % (password)

        endpoint_data = {
            'connection':
                connection,
        }
        return endpoint_data

    @helm_context
    def get_nova_endpoint_data(self):
        nova_operator = self.chart_operators[self.HELM_CHART_NOVA]
        endpoint_data = {
            'endpoint_override':
                'http://nova-api-internal.openstack.svc.cluster.local:80',
            'region_name':
                nova_operator.get_region_name(),
        }
        return endpoint_data

    @helm_context
    def get_nova_oslo_messaging_data(self):
        nova_operator = self.chart_operators[self.HELM_CHART_NOVA]
        endpoints_overrides = nova_operator._get_endpoints_overrides()
        auth_data = {
            'host':
                'rabbitmq.openstack.svc.cluster.local',
            'port':
                5672,
            'virt_host':
                'nova',
            'username':
                endpoints_overrides['oslo_messaging']['auth']['nova']
                ['username'],
            'password':
                endpoints_overrides['oslo_messaging']['auth']['nova']
                ['password'],
        }
        return auth_data

    @helm_context
    def get_cinder_endpoint_data(self):
        cinder_operator = self.chart_operators[self.HELM_CHART_CINDER]
        endpoint_data = {
            'region_name':
                cinder_operator.get_region_name(),
            'service_name':
                cinder_operator.get_service_name_v2(),
            'service_type':
                cinder_operator.get_service_type_v2(),
        }
        return endpoint_data

    @helm_context
    def get_glance_endpoint_data(self):
        glance_operator = self.chart_operators[self.HELM_CHART_GLANCE]
        endpoint_data = {
            'region_name':
                glance_operator.get_region_name(),
            'service_name':
                glance_operator.get_service_name(),
            'service_type':
                glance_operator.get_service_type(),
        }
        return endpoint_data

    @helm_context
    def get_neutron_endpoint_data(self):
        neutron_operator = self.chart_operators[self.HELM_CHART_NEUTRON]
        endpoint_data = {
            'region_name':
                neutron_operator.get_region_name(),
        }
        return endpoint_data

    @helm_context
    def get_heat_endpoint_data(self):
        heat_operator = self.chart_operators[self.HELM_CHART_HEAT]
        endpoint_data = {
            'region_name':
                heat_operator.get_region_name(),
        }
        return endpoint_data

    @helm_context
    def get_ceilometer_endpoint_data(self):
        ceilometer_operator = \
            self.chart_operators[self.HELM_CHART_CEILOMETER]
        endpoint_data = {
            'region_name':
                ceilometer_operator.get_region_name(),
        }
        return endpoint_data

    @helm_context
    def get_dcdbsync_endpoint_data(self):
        dcdbsync_operator = self.chart_operators[self.HELM_CHART_DCDBSYNC]
        endpoints_overrides = dcdbsync_operator._get_endpoints_overrides()
        endpoint_data = {
            'keystone_password':
                endpoints_overrides['identity']['auth']['dcdbsync']
                ['password'],
        }
        return endpoint_data
