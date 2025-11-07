#
# Copyright (c) 2018-2024 Wind River Systems, Inc.
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

from oslo_log import log as logging
from sysinv.common import exception
from sysinv.common import plugin_manager
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


LOCK_NAME = 'HelmOperator'


class HelmOperator(object):
    """Class to encapsulate helm override operations for System Inventory"""

    def __init__(self, dbapi=None):
        self.dbapi = dbapi
        self.plugins = plugin_manager.PluginManager()

        # Audit discoverable app plugins to remove any stale plugins that may
        # have been removed since this host was last tasked to manage
        # applications
        self.plugins.audit_plugins(self.dbapi)

        # Find all plugins for apps, charts per app, and fluxcd operators
        self.discover_plugins()

    @utils.synchronized(LOCK_NAME)
    def discover_plugins(self):
        self.plugins.discover_plugins(self)

    def get_app_lifecycle_operator(self, plugin_name):
        """Return an AppLifecycle operator based on app name"""
        plugin_name = utils.find_app_plugin_name(plugin_name)
        plugin = self.plugins.get_plugin(plugin_manager.PLUGIN_NS_LIFECYCLE_OPS, plugin_name)
        return plugin.operator

    def get_fluxcd_kustomize_operator(self, plugin_name):
        """Return a kustomize operator based on app name"""

        plugin_name = utils.find_app_plugin_name(plugin_name)
        plugin = self.plugins.get_plugin(plugin_manager.PLUGIN_NS_KUSTOMIZE_OPS, plugin_name)
        return plugin.operator

    def get_helm_system_application_relation(self, plugin_name):
        return self.plugins.get_subnamespace_relation_by_plugin_name(
            plugin_manager.PLUGIN_NS_HELM_APPLICATIONS,
            plugin_name
        )

    def get_chart_operator(self, plugin_name):
        plugin = self.plugins.get_plugin(
            namespace=plugin_manager.PLUGIN_NS_HELM_APPLICATIONS,
            plugin_name=plugin_name,
            fallback_to_generic=False
        )
        if plugin:
            return plugin.operator
        return None

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
        chart_op = self.get_chart_operator(chart_name)
        if chart_op:
            app_plugin_name = utils.find_app_plugin_name(app_name)
            namespaces = chart_op.get_namespaces_by_app(app_plugin_name)
        return namespaces

    def get_helm_chart_namespaces(self, chart_name):
        """Get supported chart namespaces.

        This method retrieves the namespace supported by a given chart.

        :param chart_name: name of the chart
        :returns: list of supported namespaces that associated overrides may be
                  provided.
        """

        namespaces = []
        chart_op = self.get_chart_operator(chart_name)
        if chart_op:
            namespaces = chart_op.SUPPORTED_NAMESPACES
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
        chart_op = self.get_chart_operator(chart_name)
        if chart_op:
            try:
                overrides.update(chart_op.get_overrides(cnamespace))
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
        helm_system_applications = self.get_helm_system_application_relation(plugin_name)
        if helm_system_applications:
            for chart_name in helm_system_applications:
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

        helm_system_applications = self.get_helm_system_application_relation(plugin_name)
        for chart_name in helm_system_applications:
            try:
                overrides.update(
                    {chart_name: self._get_helm_chart_overrides(chart_name, cnamespace)}
                )
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

        chart_op = self.get_chart_operator(chart_name)
        if chart_op:
            namespaces = chart_op.SUPPORTED_NAMESPACES
            if cnamespace and cnamespace not in namespaces:
                LOG.exception("The %s chart does not support namespace: %s" %
                              (chart_name, cnamespace))
                return
            try:
                overrides = self._get_helm_chart_overrides(chart_name, cnamespace)
                self._write_chart_overrides(path, chart_name, cnamespace, overrides)
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

        generated_files = []
        app, plugin_name = self._find_kube_app_and_app_plugin_name(app_name)

        # Get a kustomize operator to provide a single point of
        # manipulation for the chart resources
        kustomize_op = self.get_fluxcd_kustomize_operator(app.name)

        # Load the FluxCD manifests into the operator
        fluxcd_manifests_dir = utils.generate_synced_fluxcd_manifests_fqpn(
            app.name, app.app_version)
        kustomize_op.load(fluxcd_manifests_dir)

        if self.get_helm_system_application_relation(plugin_name):
            app_overrides = self._get_helm_application_overrides(plugin_name, cnamespace)
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

                override_file = self._write_chart_overrides(
                    path, chart_name, cnamespace, overrides)
                generated_files.append(override_file)

                # Update manifest docs based on the plugin directives. If the
                # application does not provide a manifest operator, the
                # GenericFluxCDKustomizeOperator is used and chart specific
                # operations can be skipped.
                if kustomize_op.APP:
                    chart_op = self.get_chart_operator(chart_name)
                    if chart_op:
                        chart_op.execute_kustomize_updates(kustomize_op)

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

                override_file = self._write_chart_overrides(
                    path, chart.name, cnamespace, user_overrides)
                generated_files.append(override_file)

        # Write the kustomization doc overrides and a unified manifest for deletion.
        kustomize_op.save_kustomization_updates()
        kustomize_op.save_release_cleanup_data()

        return generated_files

    def _find_kube_app_and_app_plugin_name(self, app_name):
        return utils.find_kube_app(self.dbapi, app_name), \
               utils.find_app_plugin_name(app_name)

    def remove_helm_chart_overrides(self, path, chart_name, cnamespace=None):
        """Remove the overrides files for a chart"""
        chart_op = self.get_chart_operator(chart_name)
        if chart_op:
            namespaces = chart_op.SUPPORTED_NAMESPACES

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
            filepath = ""
            try:
                filepath = self._write_overrides(path, filename, values)
            except Exception as e:
                LOG.exception("failed to write %s overrides: %s: %s" % (
                    chart_name, filename, e))

            return filepath

        filename = helm_utils.build_overrides_filename(chart_name, cnamespace)

        # If the chart has just one namespace there is no need to add
        # the top level reference to it.
        if len(overrides) == 1:
            filepath = _write_file(filename,
                                   overrides[next(iter(overrides))])
        else:
            filepath = _write_file(filename, overrides)

        return filepath

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

        return filepath

    def _remove_overrides(self, path, filename):
        """Remove a single overrides file. """

        filepath = os.path.join(path, filename)
        try:
            if os.path.exists(filepath):
                os.unlink(filepath)
        except Exception:
            LOG.exception("failed to delete overrides file: %s" % filepath)
            raise


class HelmOperatorData(object):
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

    def __init__(self, helm_operator=None):
        self.helm_op = helm_operator

    @helm_context
    def get_keystone_auth_data(self):
        keystone_operator = self.helm_op.get_chart_operator(self.HELM_CHART_KEYSTONE)

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
        keystone_operator = self.helm_op.get_chart_operator(self.HELM_CHART_KEYSTONE)
        endpoint_data = {
            'endpoint_override':
                'http://keystone.openstack.svc.cluster.local:80',
            'region_name':
                keystone_operator.get_region_name(),
        }
        return endpoint_data

    @helm_context
    def get_keystone_oslo_db_data(self):
        keystone_operator = self.helm_op.get_chart_operator(self.HELM_CHART_KEYSTONE)
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
        nova_operator = self.helm_op.get_chart_operator(self.HELM_CHART_NOVA)
        endpoint_data = {
            'endpoint_override':
                'http://nova-api-internal.openstack.svc.cluster.local:80',
            'region_name':
                nova_operator.get_region_name(),
        }
        return endpoint_data

    @helm_context
    def get_nova_oslo_messaging_data(self):
        nova_operator = self.helm_op.get_chart_operator(self.HELM_CHART_NOVA)
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
        cinder_operator = self.helm_op.get_chart_operator(self.HELM_CHART_CINDER)
        endpoint_data = {
            'region_name':
                cinder_operator.get_region_name(),
            'service_name':
                cinder_operator.get_service_name(),
            'service_type':
                cinder_operator.get_service_type(),
        }
        return endpoint_data

    @helm_context
    def get_glance_endpoint_data(self):
        glance_operator = self.helm_op.get_chart_operator(self.HELM_CHART_GLANCE)
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
        neutron_operator = self.helm_op.get_chart_operator(self.HELM_CHART_NEUTRON)
        endpoint_data = {
            'region_name':
                neutron_operator.get_region_name(),
        }
        return endpoint_data

    @helm_context
    def get_heat_endpoint_data(self):
        heat_operator = self.helm_op.get_chart_operator(self.HELM_CHART_HEAT)
        endpoint_data = {
            'region_name':
                heat_operator.get_region_name(),
        }
        return endpoint_data

    @helm_context
    def get_ceilometer_endpoint_data(self):
        ceilometer_operator = self.helm_op.get_chart_operator(self.HELM_CHART_CEILOMETER)
        endpoint_data = {
            'region_name':
                ceilometer_operator.get_region_name(),
        }
        return endpoint_data

    @helm_context
    def get_dcdbsync_endpoint_data(self):
        dcdbsync_operator = self.helm_op.get_chart_operator(self.HELM_CHART_DCDBSYNC)
        endpoints_overrides = dcdbsync_operator._get_endpoints_overrides()
        endpoint_data = {
            'keystone_password':
                endpoints_overrides['identity']['auth']['dcdbsync']
                ['password'],
        }
        return endpoint_data
