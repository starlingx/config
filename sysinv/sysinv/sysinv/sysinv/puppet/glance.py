#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os

from oslo_utils import strutils
from urlparse import urlparse
from sysinv.common import constants
from sysinv.common import exception
from sysinv.openstack.common import log as logging
from . import openstack

LOG = logging.getLogger(__name__)


class GlancePuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for glance configuration"""

    SERVICE_NAME = 'glance'
    SERVICE_TYPE = 'image'
    SERVICE_PORT = 9292
    SERVICE_KS_USERNAME = 'glance'

    ADMIN_SERVICE = 'CGCS'
    ADMIN_USER = 'admin'

    def get_static_config(self):
        dbuser = self._get_database_username(self.SERVICE_NAME)

        return {
            'glance::db::postgresql::user': dbuser,

            'glance::api::authtoken::username': self.SERVICE_KS_USERNAME,

            'glance::registry::authtoken::username': self.SERVICE_KS_USERNAME,
        }

    def get_secure_static_config(self):
        dbpass = self._get_database_password(self.SERVICE_NAME)
        kspass = self._get_service_password(self.SERVICE_NAME)

        config = {
            'glance::db::postgresql::password': dbpass,

            'glance::keystone::auth::password': kspass,
            'glance::keystone::authtoken::password': kspass,

            'glance::api::authtoken::password': kspass,

            'glance::registry::authtoken::password': kspass,
        }

        # set remote registry admin_password for subcloud
        admin_password = self._get_keyring_password(self.ADMIN_SERVICE,
                                                    self.ADMIN_USER)
        config.update({
            'glance::api::admin_password': admin_password,
        })

        return config

    def get_system_config(self):

        # TODO (rchurch): Add region check... Is there an install without glance?
        enabled_backends = []
        stores = [constants.GLANCE_BACKEND_HTTP]
        data_api = constants.GLANCE_SQLALCHEMY_DATA_API
        pipeline = constants.GLANCE_DEFAULT_PIPELINE
        registry_host = constants.GLANCE_LOCAL_REGISTRY
        remote_registry_region_name = None
        rbd_store_pool = None
        rbd_store_ceph_conf = None

        is_service_enabled = False
        for storage_backend in self.dbapi.storage_backend_get_list():
            if (storage_backend.backend == constants.SB_TYPE_FILE and
                (storage_backend.services and
                 constants.SB_SVC_GLANCE in storage_backend.services)):
                is_service_enabled = True
                enabled_backends.append(storage_backend.backend)
                stores.append(storage_backend.backend)
            elif (storage_backend.backend == constants.SB_TYPE_CEPH and
                  (storage_backend.services and
                   constants.SB_SVC_GLANCE in storage_backend.services)):
                is_service_enabled = True
                enabled_backends.append(constants.GLANCE_BACKEND_RBD)
                stores.append(constants.GLANCE_BACKEND_RBD)
                # For internal ceph backend, the default "images" glance pool
                # and default "/etc/ceph/ceph.conf" config file will be used.
            elif (storage_backend.backend == constants.SB_TYPE_CEPH_EXTERNAL and
                  (storage_backend.services and
                   constants.SB_SVC_GLANCE in storage_backend.services)):
                is_service_enabled = True
                enabled_backends.append(constants.GLANCE_BACKEND_RBD)
                stores.append(constants.GLANCE_BACKEND_RBD)
                ceph_ext_obj = self.dbapi.storage_ceph_external_get(
                    storage_backend.id)
                rbd_store_pool = storage_backend.capabilities.get('glance_pool')
                rbd_store_ceph_conf = constants.CEPH_CONF_PATH + os.path.basename(ceph_ext_obj.ceph_conf)

        if self.get_glance_cached_status():
            stores.append(constants.GLANCE_BACKEND_GLANCE)
            data_api = constants.GLANCE_REGISTRY_DATA_API
            pipeline = constants.GLANCE_CACHE_PIPELINE
            registry_host = self._keystone_auth_address()
            remote_registry_region_name = self._keystone_region_name()

        # update remote registry for subcloud
        if (self._distributed_cloud_role() ==
                constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD):
            registry_host = self._get_system_controller_host()
            remote_registry_region_name = constants.SYSTEM_CONTROLLER_REGION

        if constants.GLANCE_BACKEND_RBD in enabled_backends:
            default_store = constants.GLANCE_BACKEND_RBD
        else:
            default_store = constants.GLANCE_BACKEND_FILE

        ksuser = self._get_service_user_name(self.SERVICE_NAME)

        config = {
            'glance::api::os_region_name': self.get_region_name(),
            'glance::api::default_store': default_store,
            'glance::api::stores': stores,

            'glance::keystone::auth::public_url': self.get_public_url(),
            'glance::keystone::auth::internal_url': self.get_internal_url(),
            'glance::keystone::auth::admin_url': self.get_admin_url(),
            'glance::keystone::auth::region': self._endpoint_region_name(),
            'glance::keystone::auth::tenant':
                self._get_service_tenant_name(),
            'glance::keystone::auth::auth_name': ksuser,
            'glance::keystone::auth::configure_user': self.to_configure_user(),
            'glance::keystone::auth::configure_user_role':
                self.to_configure_user_role(),

            'glance::keystone::authtoken::auth_url':
                self._keystone_identity_uri(),
            'glance::keystone::authtoken::auth_uri':
                self._keystone_auth_uri(),

            'glance::api::authtoken::auth_uri':
                self._keystone_auth_uri(),
            'glance::api::authtoken::auth_url':
                self._keystone_identity_uri(),
            'glance::api::authtoken::username': ksuser,
            'glance::api::authtoken::user_domain_name':
                self._get_service_user_domain_name(),
            'glance::api::authtoken::project_domain_name':
                self._get_service_project_domain_name(),
            'glance::api::authtoken::project_name':
                self._get_service_tenant_name(),
            'glance::api::authtoken::region_name':
                self._api_authtoken_region_name(),

            'glance::registry::authtoken::auth_uri':
                self._keystone_auth_uri(),
            'glance::registry::authtoken::auth_url':
                self._keystone_identity_uri(),
            'glance::registry::authtoken::username': ksuser,
            'glance::registry::authtoken::user_domain_name':
                self._get_service_user_domain_name(),
            'glance::registry::authtoken::project_domain_name':
                self._get_service_project_domain_name(),
            'glance::registry::authtoken::project_name':
                self._get_service_tenant_name(),
            'glance::registry::authtoken::region_name':
                self._registry_authtoken_region_name(),

            'openstack::glance::params::api_host':
                self._get_glance_address(),
            'openstack::glance::params::enabled_backends':
                enabled_backends,
            'openstack::glance::params::service_enabled':
                is_service_enabled,

            'openstack::glance::params::region_name':
                self.get_region_name(),
            'openstack::glance::params::service_create':
                self._to_create_services(),
            'glance::api::pipeline': pipeline,
            'glance::api::data_api': data_api,
            'glance::api::remote_registry_region_name':
                remote_registry_region_name,
            'openstack::glance::params::configured_registry_host':
                registry_host,
            'openstack::glance::params::glance_cached':
                self.get_glance_cached_status(),
        }

        if rbd_store_pool and rbd_store_ceph_conf:
            config.update({'openstack::glance::params::rbd_store_pool':
                               rbd_store_pool,
                           'openstack::glance::params::rbd_store_ceph_conf':
                               rbd_store_ceph_conf, })

        # set remote registry auth_url for subcloud
        if (self._distributed_cloud_role() ==
                constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD):
            # TODO (aning): with each subcloud has its own keystone, subcloud
            # no longer knows SystemController's keystone admin url. We need
            # to have that information in sub cloud config file eventually.
            # For now it's assumed it's on http and on port 5000
            api_auth_url = self._format_url_address(
                self._get_system_controller_host())
            api_auth_url = 'http://' + api_auth_url + ':5000/v3'

            config.update({
                'glance::api::auth_url': api_auth_url,
            })

        return config

    def get_secure_system_config(self):
        config = {
            'glance::database_connection':
                self._format_database_connection(self.SERVICE_NAME),
            'glance::api::database_connection':
                self._format_database_connection(self.SERVICE_NAME),
            'glance::registry::database_connection':
                self._format_database_connection(self.SERVICE_NAME),
        }
        return config

    def to_configure_user(self):
        if (self._region_config() and
                    self.SERVICE_TYPE in self._get_shared_services()):
            return False
        return True

    def to_configure_user_role(self):
        if (self._region_config() and
                    self.SERVICE_TYPE in self._get_shared_services()):
            return False
        return True

    def _endpoint_region_name(self):
        if (self._distributed_cloud_role() ==
                constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER):
            return constants.SYSTEM_CONTROLLER_REGION
        else:
            return self._region_name()

    def _api_authtoken_region_name(self):
        if (self._distributed_cloud_role() ==
                constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER):
            return constants.REGION_ONE_NAME
        else:
            return self._region_name()

    def _registry_authtoken_region_name(self):
        if (self._distributed_cloud_role() ==
                constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER):
            return constants.REGION_ONE_NAME
        else:
            return self._region_name()

    def get_public_url(self):
        if (self._region_config() and
                    self.SERVICE_TYPE in self._get_shared_services()):
            return self._get_public_url_from_service_config(self.SERVICE_NAME)
        else:
            return self._format_public_endpoint(self.SERVICE_PORT)

    def get_internal_url(self):
        if (self._region_config() and
                    self.SERVICE_TYPE in self._get_shared_services()):
            return self._get_internal_url_from_service_config(self.SERVICE_NAME)
        else:
            address = self._format_url_address(self._get_glance_address())
            return self._format_private_endpoint(self.SERVICE_PORT,
                                             address=address)

    def get_admin_url(self):
        if (self._region_config() and
                    self.SERVICE_TYPE in self._get_shared_services()):
            return self._get_admin_url_from_service_config(self.SERVICE_NAME)
        else:
            address = self._format_url_address(self._get_glance_address())
            return self._format_private_endpoint(self.SERVICE_PORT,
                                             address=address)

    def _get_glance_address(self):
        # Obtain NFS infrastructure address if configured, otherwise fallback
        # to the management controller address
        try:
            return self._get_address_by_name(
                constants.CONTROLLER_CGCS_NFS,
                constants.NETWORK_TYPE_INFRA).address
        except exception.AddressNotFoundByName:
            return self._get_management_address()

    def get_region_name(self):
        return self._get_service_region_name(self.SERVICE_NAME)

    def get_glance_address(self):
        if (self._region_config() and
                self.get_region_name() == self._keystone_region_name()):
            url = urlparse(self.get_glance_url())
            return url.hostname
        else:
            return self._get_glance_address()

    def get_glance_url(self):
        return self.get_internal_url()

    def get_service_name(self):
        return self._get_configured_service_name(self.SERVICE_NAME)

    def get_service_type(self):
        service_type = self._get_configured_service_type(self.SERVICE_NAME)
        if service_type is None:
            return self.SERVICE_TYPE
        else:
            return service_type

    def get_glance_cached_status(self):
        service_config = None
        if self._region_config():
            service_config = self._get_service_config(self.SERVICE_NAME)

        if service_config is None:
            return False

        glance_cached_status = service_config.capabilities.get(
            'glance_cached', False)

        return strutils.bool_from_string(glance_cached_status, strict=True)
