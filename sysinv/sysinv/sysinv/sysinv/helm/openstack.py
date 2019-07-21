#
# Copyright (c) 2018-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import keyring
import os
import subprocess

from Crypto.PublicKey import RSA
from sysinv.helm import base
from sysinv.helm import common

from oslo_log import log
from oslo_serialization import jsonutils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common.storage_backend_conf import K8RbdProvisioner
from sqlalchemy.orm.exc import NoResultFound

LOG = log.getLogger(__name__)


class OpenstackBaseHelm(base.BaseHelm):
    """Class to encapsulate Openstack service operations for helm"""

    SUPPORTED_NAMESPACES = \
        base.BaseHelm.SUPPORTED_NAMESPACES + [common.HELM_NS_OPENSTACK]
    SUPPORTED_APP_NAMESPACES = {
        constants.HELM_APP_OPENSTACK:
            base.BaseHelm.SUPPORTED_NAMESPACES + [common.HELM_NS_OPENSTACK]
    }

    def _get_service_config(self, service):
        configs = self.context.setdefault('_service_configs', {})
        if service not in configs:
            configs[service] = self._get_service(service)
        return configs[service]

    def _get_service_parameters(self, service=None):
        service_parameters = []
        if self.dbapi is None:
            return service_parameters
        try:
            service_parameters = self.dbapi.service_parameter_get_all(
                service=service)
        # the service parameter has not been added
        except NoResultFound:
            pass
        return service_parameters

    def _get_service_parameter_configs(self, service):
        configs = self.context.setdefault('_service_params', {})
        if service not in configs:
            params = self._get_service_parameters(service)
            if params:
                configs[service] = params
            else:
                return None
        return configs[service]

    @staticmethod
    def _service_parameter_lookup_one(service_parameters, section, name,
                                      default):
        for param in service_parameters:
            if param['section'] == section and param['name'] == name:
                return param['value']
        return default

    def _get_admin_user_name(self):
        keystone_operator = self._operator.chart_operators[
            common.HELM_CHART_KEYSTONE]
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
            app = self.dbapi.kube_app_get(constants.HELM_APP_OPENSTACK)
            override = self.dbapi.helm_override_get(app_id=app.id,
                                                    name=chart,
                                                    namespace=namespace)
        except exception.HelmOverrideNotFound:
            # Override for this chart not found, so create one
            try:
                values = {
                    'name': chart,
                    'namespace': namespace,
                    'app_id': app.id,
                }
                override = self.dbapi.helm_override_create(values=values)
            except Exception as e:
                LOG.exception(e)
                return None

        password = override.system_overrides.get(field, None)
        if password:
            return password.encode('utf8', 'strict')

        # The password is not present, dump from inactive app if available,
        # otherwise generate one and store it to the override
        try:
            inactive_apps = self.dbapi.kube_app_get_inactive(
                constants.HELM_APP_OPENSTACK)
            app_override = self.dbapi.helm_override_get(app_id=inactive_apps[0].id,
                                                        name=chart,
                                                        namespace=namespace)
            password = app_override.system_overrides.get(field, None)
        except (IndexError, exception.HelmOverrideNotFound):
            # No inactive app or no overrides for the inactive app
            pass

        if not password:
            password = self._generate_random_password()
        values = {'system_overrides': override.system_overrides}
        values['system_overrides'].update({
            field: password,
        })
        try:
            self.dbapi.helm_override_update(
                app_id=app.id, name=chart, namespace=namespace, values=values)
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

    def _get_file_content(self, filename):
        file_contents = ''
        with open(filename) as f:
            file_contents = f.read()
        return file_contents

    def _get_endpoint_public_tls(self):
        overrides = {}
        if (os.path.exists(constants.OPENSTACK_CERT_FILE) and
                os.path.exists(constants.OPENSTACK_CERT_KEY_FILE)):
            overrides.update({
                'crt': self._get_file_content(constants.OPENSTACK_CERT_FILE),
                'key': self._get_file_content(
                    constants.OPENSTACK_CERT_KEY_FILE),
            })
        if os.path.exists(constants.OPENSTACK_CERT_CA_FILE):
            overrides.update({
                'ca': self._get_file_content(constants.OPENSTACK_CERT_CA_FILE),
            })
        return overrides

    def _get_endpoints_host_fqdn_overrides(self, service_name):
        overrides = {'public': {}}
        endpoint_domain = self._get_service_parameter(
            constants.SERVICE_TYPE_OPENSTACK,
            constants.SERVICE_PARAM_SECTION_OPENSTACK_HELM,
            constants.SERVICE_PARAM_NAME_ENDPOINT_DOMAIN)
        if endpoint_domain is not None:
            overrides['public'].update({
                'host': service_name + '.' + str(endpoint_domain.value).lower()
            })

        # Get TLS certificate files if installed
        cert = None
        try:
            cert = self.dbapi.certificate_get_by_certtype(
                constants.CERT_MODE_OPENSTACK)
        except exception.CertificateTypeNotFound:
            pass
        if cert is not None:
            tls_overrides = self._get_endpoint_public_tls()
            if tls_overrides:
                overrides['public'].update({
                    'tls': tls_overrides
                })
        return overrides

    def _get_endpoints_scheme_public_overrides(self):
        overrides = {}
        if self._https_enabled():
            overrides = {
                'public': 'https'
            }
        return overrides

    def _get_endpoints_port_api_public_overrides(self):
        overrides = {}
        if self._https_enabled():
            overrides = {
                'api': {
                    'public': 443
                }
            }
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
            app = self.dbapi.kube_app_get(constants.HELM_APP_OPENSTACK)
            override = self.dbapi.helm_override_get(app_id=app.id,
                                                    name=chart,
                                                    namespace=namespace)
        except exception.HelmOverrideNotFound:
            # Override for this chart not found, so create one
            values = {
                'name': chart,
                'namespace': namespace,
                'app_id': app.id
            }
            override = self.dbapi.helm_override_create(values=values)

        privatekey = override.system_overrides.get('privatekey', None)
        publickey = override.system_overrides.get('publickey', None)

        if privatekey and publickey:
            return str(privatekey), str(publickey)

        # ssh keys are not set, dump from inactive app if available,
        # otherwise generate them and store in overrides
        newprivatekey = None
        newpublickey = None
        try:
            inactive_apps = self.dbapi.kube_app_get_inactive(
                constants.HELM_APP_OPENSTACK)
            app_override = self.dbapi.helm_override_get(app_id=inactive_apps[0].id,
                                                        name=chart,
                                                        namespace=namespace)
            newprivatekey = str(app_override.system_overrides.get('privatekey', None))
            newpublickey = str(app_override.system_overrides.get('publickey', None))
        except (IndexError, exception.HelmOverrideNotFound):
            # No inactive app or no overrides for the inactive app
            pass

        if not newprivatekey or not newprivatekey:
            key = RSA.generate(2048)
            pubkey = key.publickey()
            newprivatekey = key.exportKey('PEM')
            newpublickey = pubkey.exportKey('OpenSSH')
        values = {'system_overrides': override.system_overrides}
        values['system_overrides'].update({'privatekey': newprivatekey,
                                           'publickey': newpublickey})
        self.dbapi.helm_override_update(
            app_id=app.id, name=chart, namespace=namespace, values=values)

        return newprivatekey, newpublickey

    def _oslo_multistring_override(self, name=None, values=[]):
        """
        Generate helm multistring dictionary override for specified option
        name with multiple values.

        This generates oslo_config.MultiStringOpt() compatible config
        with multiple input values. This routine JSON encodes each value for
        complex types (eg, dict, list, set).

        Return a multistring type formatted dictionary override.
        """
        override = None
        if name is None or not values:
            return override

        mvalues = []
        for value in values:
            if isinstance(value, (dict, list, set)):
                mvalues.append(jsonutils.dumps(value))
            else:
                mvalues.append(value)

        override = {
            name: {'type': 'multistring',
                   'values': mvalues,
                   }
        }
        return override

    def _get_public_protocol(self):
        return 'https' if self._https_enabled() else 'http'

    def _get_service_default_dns_name(self, service):
        return "{}.{}.svc.{}".format(service, common.HELM_NS_OPENSTACK,
                                     constants.DEFAULT_DNS_SERVICE_DOMAIN)

    def _get_mount_uefi_overrides(self):

        # This path depends on OVMF packages and for starlingx
        # we don't care about aarch64.
        # This path will be used by nova-compute and libvirt pods.
        uefi_loader_path = "/usr/share/OVMF"

        uefi_config = {
            'volumes': [
                {
                    'name': 'ovmf',
                    'hostPath': {
                        'path': uefi_loader_path
                    }
                }
            ],
            'volumeMounts': [
                {
                    'name': 'ovmf',
                    'mountPath': uefi_loader_path
                },
            ]
        }
        return uefi_config

    def _get_ceph_client_overrides(self):
        # A secret is required by the chart for ceph client access. Use the
        # secret for the kube-rbd pool associated with the primary ceph tier
        return {
            'user_secret_name':
            K8RbdProvisioner.get_user_secret_name({
                'name': constants.SB_DEFAULT_NAMES[constants.SB_TYPE_CEPH]})
        }

    def execute_manifest_updates(self, operator):
        """
        Update the elements of the armada manifest.

        This allows a helm chart plugin to use the ArmadaManifestOperator to
        make dynamic structural changes to the application manifest based on the
        current conditions in the platform

        Changes include updates to manifest documents for the following schemas:
        armada/Manifest/v1, armada/ChartGroup/v1, armada/Chart/v1.

        :param operator: an instance of the ArmadaManifestOperator
        """
        if not self._is_enabled(operator.APP, self.CHART,
                                common.HELM_NS_OPENSTACK):
            operator.chart_group_chart_delete(
                operator.CHART_GROUPS_LUT[self.CHART],
                operator.CHARTS_LUT[self.CHART])

    def _is_enabled(self, app_name, chart_name, namespace):
        """
        Check if the chart is enable at a system level

        :param app_name: Application name
        :param chart_name: Chart supplied with the application
        :param namespace: Namespace where the chart will be executed

        Returns true by default if an exception occurs as most charts are
        enabled.
        """
        return super(OpenstackBaseHelm, self)._is_enabled(
            app_name, chart_name, namespace)
