#
# Copyright (c) 2017-2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import abc
import os

from sysinv.common import constants
from sysinv.common import utils as cutils
from sysinv.helm import common
from sysinv.puppet import base


class OpenstackBasePuppet(base.BasePuppet):

    def _get_service_config(self, service):
        configs = self.context.setdefault('_service_configs', {})
        if service not in configs:
            configs[service] = self._get_service(service)
        return configs[service]

    def _get_service_parameter_configs(self, service):
        configs = self.context.setdefault('_service_params', {})
        if service not in configs:
            params = self._get_service_parameters(service)
            if params:
                configs[service] = params
            else:
                return None
        return configs[service]

    def _get_admin_user_name(self):
        return self._operator.keystone.get_admin_user_name()

    def _get_service_password(self, service):
        passwords = self.context.setdefault('_service_passwords', {})
        if service not in passwords:
            passwords[service] = self._get_keyring_password(
                service,
                self.DEFAULT_SERVICE_PROJECT_NAME)
        return passwords[service]

    def _get_service_user_name(self, service):
        if self._region_config():
            service_config = self._get_service_config(service)
            if (service_config is not None and
                    'user_name' in service_config.capabilities):
                return service_config.capabilities.get('user_name')
        return '%s' % service

    def _to_create_services(self):
        if self._region_config():
            service_config = self._get_service_config(
                self._operator.keystone.SERVICE_NAME)
            if (service_config is not None and
                    'region_services_create' in service_config.capabilities):
                return service_config.capabilities.get('region_services_create')
        return True

    # Once we no longer create duplicated endpoints for shared services
    # on secondary region, this function can be removed.
    def _get_public_url_from_service_config(self, service):
        url = ''
        service_config = self._get_service_config(service)
        if (service_config is not None and
                'public_uri' in service_config.capabilities):
            url = service_config.capabilities.get('public_uri')
        if url:
            protocol = self._get_public_protocol()
            old_protocol = url.split(':')[0]
            url = url.replace(old_protocol, protocol, 1)
        return url

    def _get_admin_url_from_service_config(self, service):
        url = ''
        service_config = self._get_service_config(service)
        if (service_config is not None and
                'admin_uri' in service_config.capabilities):
            url = service_config.capabilities.get('admin_uri')
        return url

    def _get_internal_url_from_service_config(self, service):
        url = ''
        service_config = self._get_service_config(service)
        if (service_config is not None and
                'internal_uri' in service_config.capabilities):
            url = service_config.capabilities.get('internal_uri')
        return url

    def _get_public_protocol(self):
        return 'https' if self._https_enabled() else 'http'

    def _get_service_default_dns_name(self, service):
        return "{}.{}.svc.{}".format(service, common.HELM_NS_OPENSTACK,
                                     constants.DEFAULT_DNS_SERVICE_DOMAIN)

    def _get_private_protocol(self):
        return 'http'

    def _get_admin_protocol(self):
        # Turn admin endpoint protocol to be https only after ansible
        # bootstrap is completed. This is because https enabled admin
        # endpoints work only after haproxy is properly configured,
        # which will happen when puppet manifest apply during
        # controller unlock. So if https is turned on during bootstrap
        # (by services' endpoint reconfiguration), the system commands
        # to add networks etc during ansible bootstrap will fail as
        # haproxy has not been configured yet.
        if os.path.isfile(constants.ANSIBLE_BOOTSTRAP_COMPLETED_FLAG) and \
            (self._distributed_cloud_role() ==
                constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER or
                self._distributed_cloud_role() ==
                constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD):

            cutils.touch(constants.ADMIN_ENDPOINT_CONFIG_REQUIRED)
            return 'https'

        return 'http'

    def _format_public_endpoint(self, port, address=None, path=None):
        protocol = self._get_public_protocol()
        if address is None:
            address = self._format_url_address(self._get_oam_address())
        return self._format_keystone_endpoint(protocol, port, address, path)

    def _format_private_endpoint(self, port, address=None, path=None):
        protocol = self._get_private_protocol()
        if address is None:
            address = self._format_url_address(self._get_management_address())
        return self._format_keystone_endpoint(protocol, port, address, path)

    def _format_admin_endpoint(self, port, address=None, path=None):
        protocol = self._get_admin_protocol()
        s_port = port
        if address is None:
            address = self._format_url_address(self._get_management_address())
        if protocol == 'https':
            s_port = s_port + 1
        return self._format_keystone_endpoint(protocol, s_port, address, path)

    def _keystone_auth_address(self):
        return self._operator.keystone.get_auth_address()

    def _keystone_auth_host(self):
        return self._operator.keystone.get_auth_host()

    def _keystone_auth_port(self):
        return self._operator.keystone.get_auth_port()

    def _keystone_auth_uri(self):
        return self._operator.keystone.get_auth_uri()

    def _keystone_identity_uri(self):
        return self._operator.keystone.get_identity_uri()

    def _keystone_region_name(self):
        return self._operator.keystone._identity_specific_region_name()

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

    def _get_service_tenant_name(self):
        return self._get_service_project_name()

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

    def _get_service_user_domain_name(self):
        return self._operator.keystone.get_service_user_domain()

    def _get_service_project_domain_name(self):
        return self._operator.keystone.get_service_project_domain()

    # Get SystemController's address of DistributedCloud.
    def _get_system_controller_addr(self):
        sys_controller_network = self.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_SYSTEM_CONTROLLER)
        sys_controller_network_addr_pool = self.dbapi.address_pool_get(
            sys_controller_network.pool_uuid)
        addr = sys_controller_network_addr_pool.floating_address
        return addr

    @staticmethod
    def _format_keystone_endpoint(protocol, port, address, path):
        url = "%s://%s:%s" % (protocol, str(address), str(port))
        if path is None:
            return url
        else:
            return "%s/%s" % (url, path)

    def _format_database_connection(self, service,
                                    address=None, database=None):
        if not address:
            address = self._get_management_address()

        if not database:
            database = service

        return "postgresql://%s:%s@%s/%s" % (
            self._get_database_username(service),
            self._get_database_password(service),
            self._format_url_address(address),
            database)

    @abc.abstractmethod
    def get_public_url(self):
        """Return the public endpoint URL for the service"""
        raise NotImplementedError()

    @abc.abstractmethod
    def get_internal_url(self):
        """Return the internal endpoint URL for the service"""
        raise NotImplementedError()

    @abc.abstractmethod
    def get_admin_url(self):
        """Return the admin endpoint URL for the service"""
        raise NotImplementedError()
