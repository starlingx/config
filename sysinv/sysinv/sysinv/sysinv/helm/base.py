#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import abc
import os
import six

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils
from sysinv.common.storage_backend_conf import StorageBackendConfig

from sysinv.openstack.common import log as logging

from sysinv.helm import common
from sysinv.helm import quoted_str

LOG = logging.getLogger('object')


@six.add_metaclass(abc.ABCMeta)
class BaseHelm(object):
    """Base class to encapsulate helm operations for chart overrides"""

    DEFAULT_REGION_NAME = 'RegionOne'
    CEPH_MON_SERVICE_PORT = 6789
    SUPPORTED_NAMESPACES = []
    SUPPORTED_APP_NAMESPACES = {}
    SYSTEM_CONTROLLER_SERVICES = [
        constants.HELM_CHART_KEYSTONE_API_PROXY,
    ]

    def __init__(self, operator):
        self._operator = operator

    @property
    def dbapi(self):
        return self._operator.dbapi

    @property
    def context(self):
        return self._operator.context

    @staticmethod
    def quoted_str(value):
        return quoted_str(value)

    def get_chart_location(self, chart_name, repo_name):
        if repo_name is None:
            repo_name = common.HELM_REPO_FOR_APPS
        return 'http://controller:{}/helm_charts/{}/{}-0.1.0.tgz'.format(
            utils.get_http_port(self.dbapi), repo_name, chart_name)

    @staticmethod
    def _generate_random_password(length=16):
        suffix = "Ti0*"
        num = (length / 2) - len(suffix) / 2
        return os.urandom(num).encode('hex') + suffix

    def _get_system(self):
        system = self.context.get('_system', None)
        if system is None:
            system = self.dbapi.isystem_get_one()
            self.context['_system'] = system
        return system

    def _https_enabled(self):
        if self.dbapi is None:
            return False

        system = self._get_system()
        return system.capabilities.get('https_enabled', False)

    def _region_config(self):
        if self.dbapi is None:
            return False

        system = self._get_system()
        return system.capabilities.get('region_config', False)

    def _distributed_cloud_role(self):
        if self.dbapi is None:
            return None

        system = self._get_system()
        return system.distributed_cloud_role

    def _region_name(self):
        """Returns the local region name of the system"""
        if self.dbapi is None:
            return self.DEFAULT_REGION_NAME

        system = self._get_system()
        return system.region_name.encode('utf8', 'strict')

    def _get_service(self, service_name):
        if self.dbapi is None:
            return None

        try:
            service = self.dbapi.service_get(service_name)
        except exception.ServiceNotFound:
            # service not configured
            return None
        return service

    def _get_shared_services(self):
        if self.dbapi is None:
            return []

        system = self._get_system()
        return system.capabilities.get('shared_services', [])

    def _get_service_parameter(self, service, section, name):
        if self.dbapi is None:
            return None

        try:
            parameter = self.dbapi.service_parameter_get_one(service=service, section=section, name=name)
        except exception.NotFound:
            return None
        except exception.MultipleResults:
            LOG.error("Multiple service parameters found for %s/%s/%s\n" %
                      (service, section, name))
            return None
        return parameter

    def _count_hosts_by_label(self, label):
        return int(self.dbapi.count_hosts_by_label(label))

    def _num_controllers(self):
        return self._count_hosts_by_label(common.LABEL_CONTROLLER)

    def _num_computes(self):
        return self._count_hosts_by_label(common.LABEL_COMPUTE)

    def _num_controllers_by_personality(self):
        return int(self.dbapi.count_hosts_by_personality(
            constants.CONTROLLER))

    def _get_address_by_name(self, name, networktype):
        """
        Retrieve an address entry by name and scoped by network type
        """
        addresses = self.context.setdefault('_address_names', {})
        address_name = utils.format_address_name(name, networktype)
        address = addresses.get(address_name)
        if address is None:
            address = self.dbapi.address_get_by_name(address_name)
            addresses[address_name] = address

        return address

    def _get_oam_address(self):
        address = self._get_address_by_name(
            constants.CONTROLLER_HOSTNAME, constants.NETWORK_TYPE_OAM)
        return address.address

    def _system_mode(self):
        return self.dbapi.isystem_get_one().system_mode

    def _get_ceph_monitor_ips(self):
        if self._system_mode() == constants.SYSTEM_MODE_SIMPLEX:
            monitors = [self._get_controller_0_management_address()]
        else:
            monitors = StorageBackendConfig.get_ceph_mon_ip_addresses(
                self.dbapi).values()
        return monitors

    def _get_formatted_ceph_monitor_ips(self):
        port = self.CEPH_MON_SERVICE_PORT
        monitor_ips = self._get_ceph_monitor_ips()
        formatted_monitor_ips = [
            utils.format_ceph_mon_address(mon, port) for mon in monitor_ips
        ]
        return formatted_monitor_ips

    def _get_management_address(self):
        address = self._get_address_by_name(
            constants.CONTROLLER_HOSTNAME, constants.NETWORK_TYPE_MGMT)
        return address.address

    def _get_controller_0_management_address(self):
        address = self._get_address_by_name(
            constants.CONTROLLER_0_HOSTNAME, constants.NETWORK_TYPE_MGMT)
        return address.address

    @staticmethod
    def _format_url_address(address):
        return utils.format_url_address(address)

    def _get_host_cpu_list(self, host, function=None, threads=False):
        """
        Retrieve a list of CPUs for the host, filtered by function and thread
        siblings (if supplied)
        """
        cpus = []
        for c in self.dbapi.icpu_get_by_ihost(host.id):
            if c.thread != 0 and not threads:
                continue
            if c.allocated_function == function or not function:
                cpus.append(c)
        return cpus

    def get_namespaces(self):
        """
        Return list of namespaces supported by this chart

        If a chart supports namespaces other than common.HELM_NS_OPENSTACK
        then it can override self.SUPPORTED_NAMESPACES as desired.
        """
        return self.SUPPORTED_NAMESPACES

    def get_namespaces_by_app(self, app_name):
        """
        Return list of namespaces supported by an applcation
        """
        if app_name in self.SUPPORTED_APP_NAMESPACES:
            return self.SUPPORTED_APP_NAMESPACES[app_name]
        else:
            return []

    def get_overrides(self, namespace=None):
        """
        Return chart-specific values overrides

        This allows a helm chart class to specify overrides (in Helm format)
        for the "values" section of a helm chart.

        May be left blank to indicate that there are no additional overrides.
        """
        return {}

    def get_meta_overrides(self, namespace, app_name=None, mode=None):
        """
        Return Armada-formatted chart-specific meta-overrides

        This allows a helm chart class to specify overrides (in Armada format)
        for things other than the "values" section of a chart.  This includes
        other sections of a chart, as well as chart groups or even the
        overall manifest itself.

        May be left blank to indicate that there are no additional overrides.
        """
        return {}
