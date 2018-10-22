#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import keyring
import subprocess

from . import base
from . import common

from sysinv.common import constants
from sysinv.common import exception


class OpenstackBaseHelm(base.BaseHelm):
    """Class to encapsulate Openstack service operations for helm"""

    def _get_service_config(self, service):
        configs = self.context.setdefault('_service_configs', {})
        if service not in configs:
            configs[service] = self._get_service(service)
        return configs[service]

    def _get_admin_user_name(self):
        keystone_operator = self._operator.chart_operators[
            constants.HELM_CHART_KEYSTONE]
        return keystone_operator.get_admin_user_name()

    def _get_identity_password(self, service, user):
        passwords = self.context.setdefault('_service_passwords', {})
        if service not in passwords:
            passwords[service] = {}

        if user not in passwords[service]:
            passwords[service][user] = self._get_keyring_password(service, user)

        return passwords[service][user]

    def _get_database_password(self, service):
        passwords = self.context.setdefault('_database_passwords', {})
        if service not in passwords:
            passwords[service] = self._get_keyring_password(service,
                                                            'database')
        return passwords[service]

    def _get_database_username(self, service):
        return 'admin-%s' % service

    def _get_keyring_password(self, service, user, pw_format=None):
        password = keyring.get_password(service, user)
        if not password:
            if pw_format == common.PASSWORD_FORMAT_CEPH:
                try:
                    cmd = ['ceph-authtool', '--gen-print-key']
                    password = subprocess.check_output(cmd).strip()
                except subprocess.CalledProcessError:
                    raise exception.SysinvException(
                        'Failed to generate ceph key')
            else:
                password = self._generate_random_password()
            keyring.set_password(service, user, password)
        # get_password() returns in unicode format, which leads to YAML
        # that Armada doesn't like.  Converting to UTF-8 is safe because
        # we generated the password originally.
        return password.encode('utf8', 'strict')

    def _get_service_region_name(self, service):
        if self._region_config():
            service_config = self._get_service_config(service)
            if (service_config is not None and
                    service_config.region_name is not None):
                return service_config.region_name

        if (self._distributed_cloud_role() ==
                constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER and
                service in self.SYSTEM_CONTROLLER_SERVICES):
            return constants.SYSTEM_CONTROLLER_REGION

        return self._region_name()

    def _get_common_users_overrides(self, service):
        overrides = {}
        for user in common.USERS:
            if user == common.USER_ADMIN:
                o_user = self._get_admin_user_name()
                o_service = common.SERVICE_ADMIN
            else:
                o_user = user
                o_service = service

            overrides.update({
                user: {
                    'region_name': self._region_name(),
                    'username': o_user,
                    'password': self._get_identity_password(o_service, o_user)
                }
            })
        return overrides

    def _get_ceph_password(self, service, user):
        passwords = self.context.setdefault('_ceph_passwords', {})
        if service not in passwords:
            passwords[service] = {}

        if user not in passwords[service]:
            passwords[service][user] = self._get_keyring_password(
                service, user, pw_format=common.PASSWORD_FORMAT_CEPH)

        return passwords[service][user]
