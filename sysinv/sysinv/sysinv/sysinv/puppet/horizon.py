#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from . import openstack

from sysinv.common import exception


class HorizonPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for horizon configuration"""

    def get_secure_static_config(self):
        return {
            'openstack::horizon::params::secret_key':
                self._generate_random_password(length=32),
        }

    def get_system_config(self):
        config = {
            'openstack::horizon::params::enable_https':
                self._https_enabled(),
            'openstack::horizon::params::openstack_host':
                self._keystone_auth_host(),

        }
        tpm_config = self._get_tpm_config()
        if tpm_config is not None:
            config.update(tpm_config)
        return config

    def _get_tpm_config(self):
        try:
            tpmconfig = self.dbapi.tpmconfig_get_one()
            if tpmconfig.tpm_path:
                return {
                    'openstack::horizon::params::tpm_object':
                        tpmconfig.tpm_path
                }
        except exception.NotFound:
            pass

        return None

    def get_public_url(self):
        # not an openstack service
        raise NotImplementedError()

    def get_internal_url(self):
        # not an openstack service
        raise NotImplementedError()

    def get_admin_url(self):
        # not an openstack service
        raise NotImplementedError()
