#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.puppet import openstack
from sysinv.common import constants


class CertAlarmPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for sysinv configuration"""
    SYSINV_SERVICE_NAME = 'sysinv'
    DC_SERVICE_NAME = 'dcmanager'

    def get_secure_static_config(self):
        sysinv_kspass = self._get_service_password(self.SYSINV_SERVICE_NAME)
        dc_kspass = self._get_service_password(self.DC_SERVICE_NAME)
        return {
            'sysinv::certalarm::local_keystone_password': sysinv_kspass,
            'sysinv::certalarm::dc_keystone_password': dc_kspass,
        }

    def get_system_config(self):
        sysinv_user = self._get_service_user_name(self.SYSINV_SERVICE_NAME)

        config = {}
        config.update({
            # The auth info for local authentication
            'sysinv::certalarm::local_keystone_auth_uri': self._keystone_auth_uri(),
            'sysinv::certalarm::local_keystone_identity_uri': self._keystone_identity_uri(),
            'sysinv::certalarm::local_keystone_project_domain': self._get_service_project_domain_name(),
            'sysinv::certalarm::local_keystone_tenant': self._get_service_project_name(),
            'sysinv::certalarm::local_keystone_user': sysinv_user,
            'sysinv::certalarm::local_keystone_user_domain': self._get_service_user_domain_name(),
            'sysinv::certalarm::local_region_name': self._keystone_region_name(),
        })

        if self._distributed_cloud_role() == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
            dc_user = self._get_service_user_name(self.DC_SERVICE_NAME),
            config.update({
                # The auth info for DC authentication
                'sysinv::certalarm::dc_keystone_auth_uri': self._keystone_auth_uri(),
                'sysinv::certalarm::dc_keystone_identity_uri': self._keystone_identity_uri(),
                'sysinv::certalarm::dc_keystone_project_domain': self._get_service_project_domain_name(),
                'sysinv::certalarm::dc_keystone_tenant': self._get_service_project_name(),
                'sysinv::certalarm::dc_keystone_user': dc_user,
                'sysinv::certalarm::dc_keystone_user_domain': self._get_service_user_domain_name(),
                'sysinv::certalarm::dc_region_name': self._keystone_region_name(),
            })

        return config

    def get_public_url(self):
        # not an openstack service
        raise NotImplementedError()

    def get_internal_url(self):
        # not an openstack service
        raise NotImplementedError()

    def get_admin_url(self):
        # not an openstack service
        raise NotImplementedError()
