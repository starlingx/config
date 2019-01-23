#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import keyring
import subprocess

from Crypto.PublicKey import RSA
from sysinv.helm import base
from sysinv.helm import common

from oslo_log import log
from sysinv.common import constants
from sysinv.common import exception

LOG = log.getLogger(__name__)


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

    def _get_configured_service_name(self, service, version=None):
        if self._region_config():
            service_config = self._get_service_config(service)
            if service_config is not None:
                name = 'service_name'
                if version is not None:
                    name = version + '_' + name
                service_name = service_config.capabilities.get(name)
                if service_name is not None:
                    return service_name
        elif version is not None:
            return service + version
        else:
            return service

    def _get_configured_service_type(self, service, version=None):
        if self._region_config():
            service_config = self._get_service_config(service)
            if service_config is not None:
                stype = 'service_type'
                if version is not None:
                    stype = version + '_' + stype
                return service_config.capabilities.get(stype)
        return None

    def _get_or_generate_password(self, chart, namespace, field):
        # Get password from the db for the specified chart overrides
        if not self.dbapi:
            return None

        try:
            override = self.dbapi.helm_override_get(name=chart,
                                                    namespace=namespace)
        except exception.HelmOverrideNotFound:
            # Override for this chart not found, so create one
            try:
                values = {
                    'name': chart,
                    'namespace': namespace,
                }
                override = self.dbapi.helm_override_create(values=values)
            except Exception as e:
                LOG.exception(e)
                return None

        password = override.system_overrides.get(field, None)
        if password:
            return password.encode('utf8', 'strict')

        # The password is not present, so generate one and store it to
        # the override
        password = self._generate_random_password()
        values = {'system_overrides': override.system_overrides}
        values['system_overrides'].update({
            field: password,
        })
        try:
            self.dbapi.helm_override_update(
                name=chart, namespace=namespace, values=values)
        except Exception as e:
            LOG.exception(e)

        return password.encode('utf8', 'strict')

    def _get_endpoints_identity_overrides(self, service_name, users):
        # Returns overrides for admin and individual users
        overrides = {}
        overrides.update(self._get_common_users_overrides(service_name))

        for user in users:
            overrides.update({
                user: {
                    'region_name': self._region_name(),
                    'password': self._get_or_generate_password(
                        service_name, common.HELM_NS_OPENSTACK, user)
                }
            })
        return overrides

    def _get_endpoints_oslo_db_overrides(self, service_name, users):
        overrides = {
            'admin': {
                'password': self._get_common_password('admin_db'),
            }
        }

        for user in users:
            overrides.update({
                user: {
                    'password': self._get_or_generate_password(
                        service_name, common.HELM_NS_OPENSTACK,
                        user + '_db'),
                }
            })

        return overrides

    def _get_endpoints_oslo_messaging_overrides(self, service_name, users):
        overrides = {
            'admin': {
                'username': 'rabbitmq-admin',
                'password': self._get_common_password('rabbitmq-admin')
            }
        }

        for user in users:
            overrides.update({
                user: {
                    'username': user + '-rabbitmq-user',
                    'password': self._get_or_generate_password(
                        service_name, common.HELM_NS_OPENSTACK,
                        user + '_rabbit')
                }
            })

        return overrides

    def _get_common_password(self, name):
        # Admin passwords are stored on keystone's helm override entry
        return self._get_or_generate_password(
            'keystone', common.HELM_NS_OPENSTACK, name)

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

    def _get_or_generate_ssh_keys(self, chart, namespace):
        try:
            override = self.dbapi.helm_override_get(name=chart,
                                                    namespace=namespace)
        except exception.HelmOverrideNotFound:
            # Override for this chart not found, so create one
            values = {
                'name': chart,
                'namespace': namespace,
            }
            override = self.dbapi.helm_override_create(values=values)

        privatekey = override.system_overrides.get('privatekey', None)
        publickey = override.system_overrides.get('publickey', None)

        if privatekey and publickey:
            return str(privatekey), str(publickey)

        # ssh keys are not set so generate them and store in overrides
        key = RSA.generate(2048)
        pubkey = key.publickey()
        newprivatekey = key.exportKey('PEM')
        newpublickey = pubkey.exportKey('OpenSSH')
        values = {'system_overrides': override.system_overrides}
        values['system_overrides'].update({'privatekey': newprivatekey,
                                           'publickey': newpublickey})
        self.dbapi.helm_override_update(
            name=chart, namespace=namespace, values=values)

        return newprivatekey, newpublickey
