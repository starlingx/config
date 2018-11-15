#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

""" System Inventory Helm Overrides Operator."""

from __future__ import absolute_import

import copy
import eventlet
import os
import subprocess
import tempfile
import yaml

from six import iteritems
from sysinv.common import constants
from sysinv.common import exception
from sysinv.openstack.common import log as logging
from . import common

# Import Chart Override Helpers:
# Chart source: https://github.com/openstack/openstack-helm.git
from . import aodh
from . import barbican
from . import ceilometer
from . import cinder
from . import glance
from . import gnocchi
from . import heat
from . import horizon
from . import ironic
from . import keystone
from . import magnum
from . import neutron
from . import nova

# Chart source: https://github.com/openstack/openstack-helm-infra.git
from . import ingress
from . import libvirt
from . import nfs_provisioner
from . import mariadb
from . import memcached
from . import openvswitch
from . import panko
from . import rabbitmq

# Chart source: Custom
from . import rbd_provisioner
from . import nova_api_proxy


LOG = logging.getLogger(__name__)


def helm_context(func):
    """Decorate to initialize the local threading context"""

    def _wrapper(self, *args, **kwargs):
        thread_context = eventlet.greenthread.getcurrent()
        setattr(thread_context, '_helm_context', dict())
        return func(self, *args, **kwargs)
    return _wrapper


class HelmOperator(object):
    """Class to encapsulate helm override operations for System Inventory"""

    def __init__(self, dbapi=None, path=None, docker_repository=None):
        if path is None:
            path = common.HELM_OVERRIDES_PATH

        # Set the primary source of docker images
        if docker_repository is None:
            # During initial development, use upstream OSH images by default and
            # switch to the STX repo when the images are validated and ready for
            # use.
            docker_repository = common.DOCKER_SRC_OSH
        else:
            valid_docker_repositories = common.DOCKER_SRCS.keys()
            if docker_repository not in valid_docker_repositories:
                raise exception.InvalidHelmDockerImageSource(
                    source=docker_repository,
                    valid_srcs=valid_docker_repositories)

        self.dbapi = dbapi
        self.path = path
        self.docker_repo_source = docker_repository

        # register chart operators for lookup
        self.chart_operators = {
            constants.HELM_CHART_AODH: aodh.AodhHelm(self),
            constants.HELM_CHART_BARBICAN: barbican.BarbicanHelm(self),
            constants.HELM_CHART_CEILOMETER: ceilometer.CeilometerHelm(self),
            constants.HELM_CHART_CINDER: cinder.CinderHelm(self),
            constants.HELM_CHART_GLANCE: glance.GlanceHelm(self),
            constants.HELM_CHART_GNOCCHI: gnocchi.GnocchiHelm(self),
            constants.HELM_CHART_HEAT: heat.HeatHelm(self),
            constants.HELM_CHART_HORIZON: horizon.HorizonHelm(self),
            constants.HELM_CHART_INGRESS: ingress.IngressHelm(self),
            constants.HELM_CHART_IRONIC: ironic.IronicHelm(self),
            constants.HELM_CHART_KEYSTONE: keystone.KeystoneHelm(self),
            constants.HELM_CHART_LIBVIRT: libvirt.LibvirtHelm(self),
            constants.HELM_CHART_MAGNUM: magnum.MagnumHelm(self),
            constants.HELM_CHART_MARIADB: mariadb.MariadbHelm(self),
            constants.HELM_CHART_MEMCACHED: memcached.MemcachedHelm(self),
            constants.HELM_CHART_NEUTRON: neutron.NeutronHelm(self),
            constants.HELM_CHART_NFS_PROVISIONER:
                nfs_provisioner.NfsProvisionerHelm(self),
            constants.HELM_CHART_NOVA: nova.NovaHelm(self),
            constants.HELM_CHART_NOVA_API_PROXY:
                nova_api_proxy.NovaApiProxyHelm(self),
            constants.HELM_CHART_OPENVSWITCH:
                openvswitch.OpenvswitchHelm(self),
            constants.HELM_CHART_PANKO: panko.PankoHelm(self),
            constants.HELM_CHART_RABBITMQ: rabbitmq.RabbitmqHelm(self),
            constants.HELM_CHART_RBD_PROVISIONER:
                rbd_provisioner.RbdProvisionerHelm(self)
        }

        # build the list of registered supported charts
        self.implemented_charts = []
        for chart in constants.SUPPORTED_HELM_CHARTS:
            if chart in self.chart_operators.keys():
                self.implemented_charts.append(chart)

    @property
    def context(self):
        thread_context = eventlet.greenthread.getcurrent()
        return getattr(thread_context, '_helm_context')

    def get_helm_chart_namespaces(self, chart_name):
        """Get supported chart namespaces.

        This method retrieves the namespace supported by a given chart.

        :param chart_name: name of the chart
        :returns: list of supported namespaces that associated overrides may be
                  provided.
        """

        namespaces = []
        if chart_name in self.implemented_charts:
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
        if chart_name in self.implemented_charts:
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
        if app_name in constants.SUPPORTED_HELM_APP_NAMES:
            for chart_name in constants.SUPPORTED_HELM_APP_CHARTS[app_name]:
                if chart_name in self.implemented_charts:
                    try:
                        app_namespaces.update({chart_name:
                                               self.get_helm_chart_namespaces(
                                                   chart_name)})
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

        If a specific namespace is requested, then only charts that that
        support that specified namespace will be returned.

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
        if app_name in constants.SUPPORTED_HELM_APP_NAMES:
            for chart_name in constants.SUPPORTED_HELM_APP_CHARTS[app_name]:
                if chart_name in self.implemented_charts:
                    try:
                        overrides.update({chart_name:
                                          self._get_helm_chart_overrides(
                                              chart_name,
                                              cnamespace)})
                    except exception.InvalidHelmNamespace as e:
                        LOG.info(e)
        return overrides

    @staticmethod
    def _add_armada_override_header(chart_name, namespace, overrides):
        new_overrides = {
            'schema': 'armada/Chart/v1',
            'metadata': {
                'schema': 'metadata/Document/v1',
                'name': namespace + '-' + chart_name
            },
            'data': {
                'values': overrides
            }
        }
        return new_overrides

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
    def generate_helm_chart_overrides(self, chart_name, cnamespace=None):
        """Generate system helm chart overrides

        This method will generate system helm chart override an write them to a
        yaml file.for use with the helm command. If the namespace is provided
        only the overrides file for that specified namespace will be written.

        :param chart_name: name of a supported chart
        :param cnamespace: (optional) namespace
        """

        if chart_name in self.implemented_charts:
            namespaces = self.chart_operators[chart_name].get_namespaces()
            if cnamespace and cnamespace not in namespaces:
                LOG.exception("The %s chart does not support namespace: %s" %
                              (chart_name, cnamespace))
                return

            try:
                overrides = self._get_helm_chart_overrides(
                    chart_name,
                    cnamespace)
                self._write_chart_overrides(chart_name,
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
    def generate_helm_application_overrides(self, app_name, cnamespace=None,
                                            armada_format=False,
                                            combined=False):
        """Create the system overrides files for a supported application

        This method will generate system helm chart overrides yaml files for a
        set of supported charts that comprise an application.. If the namespace
        is provided only the overrides files for that specified namespace will
        be written..

        :param app_name: name of the bundle of charts required to support an
                         application
        :param cnamespace: (optional) namespace
        :param armada_format: (optional) whether to emit in armada format
                              instead of helm format (with extra header)
        :param combined: (optional) whether to apply user overrides on top of
                         system overrides
        """

        if app_name in constants.SUPPORTED_HELM_APP_NAMES:
            app_overrides = self._get_helm_application_overrides(app_name,
                                                                 cnamespace)
            for (chart_name, overrides) in iteritems(app_overrides):
                if combined:
                    try:
                        db_chart = self.dbapi.helm_override_get(
                            chart_name, 'openstack')
                        user_overrides = db_chart.user_overrides
                        if user_overrides:
                            system_overrides = yaml.dump(overrides)
                            file_overrides = [system_overrides, user_overrides]
                            combined_overrides = self.merge_overrides(
                                file_overrides=file_overrides)
                            combined_overrides = yaml.load(combined_overrides)
                            overrides = copy.deepcopy(combined_overrides)
                    except exception.HelmOverrideNotFound:
                        pass

                # If armada formatting is wanted, we need to change the
                # structure of the yaml file somewhat
                if armada_format:
                    for key in overrides:
                        new_overrides = self._add_armada_override_header(
                            chart_name, key, overrides[key])
                        overrides[key] = new_overrides

                self._write_chart_overrides(chart_name, cnamespace, overrides)
        elif app_name:
            LOG.exception("%s application is not supported" % app_name)
        else:
            LOG.exception("application name is required")

    def remove_helm_chart_overrides(self, chart_name, cnamespace=None):
        """Remove the overrides files for a chart"""

        if chart_name in self.implemented_charts:
            namespaces = self.chart_operators[chart_name].get_namespaces()

            filenames = []
            if cnamespace and cnamespace in namespaces:
                filenames.append("%s-%s.yaml" % (cnamespace, chart_name))
            else:
                for n in namespaces:
                    filenames.append("%s-%s.yaml" % (n, chart_name))

            for f in filenames:
                try:
                    self._remove_overrides(f)
                except Exception as e:
                    LOG.exception("failed to remove %s overrides: %s: %s" % (
                        chart_name, f, e))
        else:
            LOG.exception("chart %s not supported for system overrides" %
                          chart_name)

    def _write_chart_overrides(self, chart_name, cnamespace, overrides):
        """Write a one or more overrides files for a chart. """

        def _write_file(filename, values):
            try:
                self._write_overrides(filename, values)
            except Exception as e:
                LOG.exception("failed to write %s overrides: %s: %s" % (
                    chart_name, filename, e))

        if cnamespace:
            _write_file("%s-%s.yaml" % (cnamespace, chart_name), overrides)
        else:
            for ns in overrides.keys():
                _write_file("%s-%s.yaml" % (ns, chart_name), overrides[ns])

    def _write_overrides(self, filename, overrides):
        """Write a single overrides file. """

        filepath = os.path.join(self.path, filename)
        try:
            fd, tmppath = tempfile.mkstemp(dir=self.path, prefix=filename,
                                           text=True)

            with open(tmppath, 'w') as f:
                yaml.dump(overrides, f, default_flow_style=False)
            os.close(fd)
            os.rename(tmppath, filepath)
        except Exception:
            LOG.exception("failed to write overrides file: %s" % filepath)
            raise

    def _remove_overrides(self, filename):
        """Remove a single overrides file. """

        filepath = os.path.join(self.path, filename)
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
