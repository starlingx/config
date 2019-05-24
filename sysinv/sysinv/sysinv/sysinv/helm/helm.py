#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

""" System Inventory Helm Overrides Operator."""

from __future__ import absolute_import

import eventlet
import os
import re
import subprocess
import tempfile
import yaml

from six import iteritems
from stevedore import extension
from sysinv.common import constants
from sysinv.common import exception
from sysinv.openstack.common import log as logging
from sysinv.helm import common


LOG = logging.getLogger(__name__)

# Number of characters to strip off from helm plugin name defined in setup.cfg,
# in order to allow controlling the order of the helm plugins, without changing
# the names of the plugins.
# The convention here is for the helm plugins to be named ###_PLUGINNAME.
HELM_PLUGIN_PREFIX_LENGTH = 4


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


class HelmOperator(object):
    """Class to encapsulate helm override operations for System Inventory"""

    def __init__(self, dbapi=None):
        self.dbapi = dbapi

        # register chart operators for lookup
        self.chart_operators = {}

        # dict containing sequence of helm charts per app
        self.helm_applications = self.get_helm_applications()

    def get_helm_applications(self):
        """Build a dictionary of supported helm applications"""

        helm_application_dict = {}
        helm_applications = extension.ExtensionManager(
            namespace='systemconfig.helm_applications',
            on_load_failure_callback=suppress_stevedore_errors
        )
        for entry_point in helm_applications.list_entry_points():
            helm_application_dict[entry_point.name] = entry_point.module_name

        supported_helm_applications = {}
        for name, namespace in helm_application_dict.items():
            supported_helm_applications[name] = []
            helm_plugins = extension.ExtensionManager(namespace=namespace, invoke_on_load=True, invoke_args=(self,))
            sorted_helm_plugins = sorted(helm_plugins.extensions, key=lambda x: x.name)
            for plugin in sorted_helm_plugins:
                plugin_name = plugin.name[HELM_PLUGIN_PREFIX_LENGTH:]
                self.chart_operators.update({plugin_name: plugin.obj})
                # Remove duplicates, keeping last occurrence only
                if plugin_name in supported_helm_applications[name]:
                    supported_helm_applications[name].remove(plugin_name)
                supported_helm_applications[name].append(plugin_name)

        return supported_helm_applications

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
            namespaces = self.chart_operators[chart_name].get_namespaces_by_app(
                app_name)
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
            namespaces = self.chart_operators[chart_name].get_namespaces()
        return namespaces

    @helm_context
    def get_helm_chart_overrides(self, chart_name, cnamespace=None):
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

        app_namespaces = {}
        if app_name in self.helm_applications:
            for chart_name in self.helm_applications[app_name]:
                try:
                    app_namespaces.update(
                        {chart_name:
                         self.get_helm_chart_namespaces_by_app(
                             chart_name, app_name)})
                except exception.InvalidHelmNamespace as e:
                    LOG.info(e)
        return app_namespaces

    @helm_context
    def get_helm_application_overrides(self, app_name, cnamespace=None):
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
        if app_name in self.helm_applications:
            for chart_name in self.helm_applications[app_name]:
                try:
                    overrides.update({chart_name:
                                      self._get_helm_chart_overrides(
                                          chart_name,
                                          cnamespace)})
                except exception.InvalidHelmNamespace as e:
                    LOG.info(e)
        return overrides

    def _get_helm_chart_location(self, chart_name, repo_name):
        """Get supported chart location.

        This method returns the download location for a given chart.

        :param chart_name: name of the chart
        :returns: a URL as location or None if the chart is not supported
        """
        if chart_name in self.chart_operators:
            return self.chart_operators[chart_name].get_chart_location(
                chart_name, repo_name)
        return None

    def _add_armada_override_header(self, chart_name, repo_name, namespace,
                                    overrides):
        use_chart_name_only = [common.HELM_NS_HELM_TOOLKIT]
        if namespace in use_chart_name_only:
            name = chart_name
        else:
            name = namespace + '-' + chart_name
        new_overrides = {
            'schema': 'armada/Chart/v1',
            'metadata': {
                'schema': 'metadata/Document/v1',
                'name': name
            },
            'data': {
                'values': overrides
            }
        }
        location = self._get_helm_chart_location(chart_name, repo_name)
        if location:
            new_overrides['data'].update({
                'source': {
                    'location': location
                }
            })
        return new_overrides

    def _get_repo_from_armada_chart_info(self, chart_name, chart_info_list):
        """ Extract the repo from the armada manifest chart location.

        :param chart_name: name of the chart from the (application list)
        :param chart_info_list: a list of chart objects containing information
            extracted from the armada manifest
        :returns: the supported StarlingX repository or None if not present
        """

        # Could be called without any armada_manifest info. Returning 'None'
        # will enable helm defaults to point to common.HELM_REPO_FOR_APPS
        repo = None
        if chart_info_list is None:
            return repo

        location = next(
            (c.location for c in chart_info_list if c.name == chart_name),
            None)

        if location:
            match = re.search('/helm_charts/(.*)/', location)
            if match:
                repo = match.group(1)
        LOG.debug("Chart %s can be found in repo: %s" % (chart_name, repo))
        return repo

    def merge_overrides(self, file_overrides=[], set_overrides=[]):
        """ Merge helm overrides together.

        :param values: A dict of different types of user override values,
                       'files' (which generally specify many overrides) and
                       'set' (which generally specify one override).
        """

        # At this point we have potentially two separate types of overrides
        # specified by system or user, values from files and values passed in
        # via --set .  We need to ensure that we call helm using the same
        # mechanisms to ensure the same behaviour.
        cmd = ['helm', 'install', '--dry-run', '--debug']

        # Process the newly-passed-in override values
        tmpfiles = []

        for value_file in file_overrides:
            # For values passed in from files, write them back out to
            # temporary files.
            tmpfile = tempfile.NamedTemporaryFile(delete=False)
            tmpfile.write(value_file)
            tmpfile.close()
            tmpfiles.append(tmpfile.name)
            cmd.extend(['--values', tmpfile.name])

        for value_set in set_overrides:
            cmd.extend(['--set', value_set])

        env = os.environ.copy()
        env['KUBECONFIG'] = '/etc/kubernetes/admin.conf'

        # Make a temporary directory with a fake chart in it
        try:
            tmpdir = tempfile.mkdtemp()
            chartfile = tmpdir + '/Chart.yaml'
            with open(chartfile, 'w') as tmpchart:
                tmpchart.write('name: mychart\napiVersion: v1\n'
                               'version: 0.1.0\n')
            cmd.append(tmpdir)

            # Apply changes by calling out to helm to do values merge
            # using a dummy chart.
            output = subprocess.check_output(cmd, env=env)

            # Check output for failure

            # Extract the info we want.
            values = output.split('USER-SUPPLIED VALUES:\n')[1].split(
                                  '\nCOMPUTED VALUES:')[0]
        except Exception:
            raise
        finally:
            os.remove(chartfile)
            os.rmdir(tmpdir)

        for tmpfile in tmpfiles:
            os.remove(tmpfile)

        return values

    @helm_context
    def generate_helm_chart_overrides(self, path, chart_name, cnamespace=None):
        """Generate system helm chart overrides

        This method will generate system helm chart override an write them to a
        yaml file.for use with the helm command. If the namespace is provided
        only the overrides file for that specified namespace will be written.

        :param chart_name: name of a supported chart
        :param cnamespace: (optional) namespace
        """

        if chart_name in self.chart_operators:
            namespaces = self.chart_operators[chart_name].get_namespaces()
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
    def generate_meta_overrides(self, chart_name, chart_namespace,
                                app_name=None, mode=None):
        overrides = {}
        if chart_name in self.chart_operators:
            try:
                overrides.update(
                    self.chart_operators[chart_name].get_meta_overrides(
                        chart_namespace, app_name, mode))
            except exception.InvalidHelmNamespace:
                raise
        return overrides

    @helm_context
    def generate_helm_application_overrides(self, path, app_name,
                                            mode=None,
                                            cnamespace=None,
                                            armada_format=False,
                                            armada_chart_info=None,
                                            combined=False):
        """Create the system overrides files for a supported application

        This method will generate system helm chart overrides yaml files for a
        set of supported charts that comprise an application.. If the namespace
        is provided only the overrides files for that specified namespace will
        be written..

        :param app_name: name of the bundle of charts required to support an
            application
        :param mode: mode to control how to apply application manifest
        :param cnamespace: (optional) namespace
        :param armada_format: (optional) whether to emit in armada format
            instead of helm format (with extra header)
        :param armada_chart_info: (optional) supporting chart information
            extracted from the armada manifest which is used to influence
            overrides
        :param combined: (optional) whether to apply user overrides on top of
            system overrides
        """

        if app_name in self.helm_applications:
            try:
                app = self.dbapi.kube_app_get(app_name)
            except exception.KubeAppNotFound:
                LOG.exception("Application %s not found." % app_name)

            app_overrides = self._get_helm_application_overrides(app_name,
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
                                file_overrides.append(yaml.dump(
                                    {chart_namespace: yaml.load(db_user_overrides)}))
                        except exception.HelmOverrideNotFound:
                            pass

                    if file_overrides:
                        # Use dump() instead of safe_dump() as the latter is
                        # not agreeable with password regex in some overrides
                        system_overrides = yaml.dump(overrides)
                        file_overrides.insert(0, system_overrides)
                        combined_overrides = self.merge_overrides(
                            file_overrides=file_overrides)
                        overrides = yaml.load(combined_overrides)

                # If armada formatting is wanted, we need to change the
                # structure of the yaml file somewhat
                if armada_format:
                    for key in overrides:
                        armada_chart_repo_name = self._get_repo_from_armada_chart_info(
                            chart_name, armada_chart_info)
                        new_overrides = self._add_armada_override_header(
                            chart_name, armada_chart_repo_name,
                            key, overrides[key])
                        overrides[key] = new_overrides
                self._write_chart_overrides(path, chart_name, cnamespace, overrides)

                # Write any meta-overrides for this chart.  These will be in
                # armada format already.
                if armada_format:
                    overrides = self.generate_meta_overrides(chart_name,
                                                             cnamespace,
                                                             app_name,
                                                             mode)
                    if overrides:
                        chart_meta_name = chart_name + '-meta'
                        self._write_chart_overrides(
                            path, chart_meta_name, cnamespace, overrides)

        elif app_name:
            LOG.exception("%s application is not supported" % app_name)
        else:
            LOG.exception("application name is required")

    def remove_helm_chart_overrides(self, path, chart_name, cnamespace=None):
        """Remove the overrides files for a chart"""

        if chart_name in self.chart_operators:
            namespaces = self.chart_operators[chart_name].get_namespaces()

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


class HelmOperatorData(HelmOperator):
    """Class to allow retrieval of helm managed data"""

    @helm_context
    def get_keystone_auth_data(self):
        keystone_operator = self.chart_operators[constants.HELM_CHART_KEYSTONE]
        auth_data = {
            'admin_user_name':
                keystone_operator.get_admin_user_name(),
            'admin_project_name':
                keystone_operator.get_admin_project_name(),
            'auth_host':
                'keystone-api.openstack.svc.cluster.local',
            'admin_user_domain':
                keystone_operator.get_admin_user_domain(),
            'admin_project_domain':
                keystone_operator.get_admin_project_domain(),
        }
        return auth_data

    @helm_context
    def get_nova_endpoint_data(self):
        nova_operator = self.chart_operators[constants.HELM_CHART_NOVA]
        endpoint_data = {
            'endpoint_override':
                'http://nova-api.openstack.svc.cluster.local:8774',
            'region_name':
                nova_operator.get_region_name(),
        }
        return endpoint_data

    @helm_context
    def get_nova_oslo_messaging_data(self):
        nova_operator = self.chart_operators[constants.HELM_CHART_NOVA]
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
        cinder_operator = self.chart_operators[constants.HELM_CHART_CINDER]
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
        glance_operator = self.chart_operators[constants.HELM_CHART_GLANCE]
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
        neutron_operator = self.chart_operators[constants.HELM_CHART_NEUTRON]
        endpoint_data = {
            'region_name':
                neutron_operator.get_region_name(),
        }
        return endpoint_data

    @helm_context
    def get_heat_endpoint_data(self):
        heat_operator = self.chart_operators[constants.HELM_CHART_HEAT]
        endpoint_data = {
            'region_name':
                heat_operator.get_region_name(),
        }
        return endpoint_data

    @helm_context
    def get_ceilometer_endpoint_data(self):
        ceilometer_operator = \
            self.chart_operators[constants.HELM_CHART_CEILOMETER]
        endpoint_data = {
            'region_name':
                ceilometer_operator.get_region_name(),
        }
        return endpoint_data
