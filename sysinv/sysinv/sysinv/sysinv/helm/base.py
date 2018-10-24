#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import abc
import os
import six

from sysinv.common import exception
from sysinv.openstack.common import log as logging

from . import common
from . import quoted_str

LOG = logging.getLogger('object')


@six.add_metaclass(abc.ABCMeta)
class BaseHelm(object):
    """Base class to encapsulate helm operations for chart overrides"""

    DEFAULT_REGION_NAME = 'RegionOne'

    def __init__(self, operator):
        self._operator = operator

    @property
    def dbapi(self):
        return self._operator.dbapi

    @property
    def context(self):
        return self._operator.context

    @property
    def docker_repo_source(self):
        return self._operator.docker_repo_source

    @property
    def docker_repo_tag(self):
        return common.DOCKER_SRCS[self.docker_repo_source][common.IMG_TAG_KEY]

    @property
    def docker_image(self):
        return "{}/{}{}:{}".format(
            common.DOCKER_SRCS[self.docker_repo_source][common.IMG_BASE_KEY],
            common.DOCKER_SRCS[self.docker_repo_source][common.IMG_PREFIX_KEY],
            self.SERVICE_NAME, self.docker_repo_tag)

    @staticmethod
    def quoted_str(value):
        return quoted_str(value)

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
