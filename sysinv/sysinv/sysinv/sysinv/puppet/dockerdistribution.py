#
# Copyright (c) 2019-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log as logging

from sysinv.common import constants
from sysinv.common import utils
from sysinv.puppet import base

LOG = logging.getLogger(__name__)

# VersionTLS12 -> tls1.2, VersionTLS13 -> tls1.3
GO_TLS_VERSION_MAP = {
    constants.SERVICE_PARAM_PLATFORM_TLS_VERSION_TLS12: 'tls1.2',
    constants.SERVICE_PARAM_PLATFORM_TLS_VERSION_TLS13: 'tls1.3',
}


class DockerDistributionPuppet(base.BasePuppet):
    """Class to encapsulate puppet operations for docker distribution"""

    def get_system_config(self):
        config = {
            'platform::dockerdistribution::params::registry_ks_endpoint':
                self._operator.keystone.get_auth_uri() + '/v3',
        }
        config.update(self._get_docker_registry_tls_config())
        return config

    def _get_docker_registry_tls_config(self):
        """Get Docker Registry TLS config from service parameters.

        Reads platform config TLS service parameters and converts
        to Go TLS format for the Docker Registry config file.
        Docker Registry v2.8+ supports minimumtls and ciphersuites
        fields natively.
        """
        tls_min_version = \
            constants.SERVICE_PARAM_PLATFORM_TLS_MIN_VERSION_DEFAULT
        tls_cipher_suite = \
            constants.SERVICE_PARAM_PLATFORM_TLS_CIPHER_SUITE_DEFAULT

        try:
            parms = self.dbapi.service_parameter_get_all(
                service=constants.SERVICE_TYPE_PLATFORM,
                section=constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG)
            for p in parms:
                if p.name == \
                        constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION:
                    tls_min_version = p.value
                elif p.name == \
                        constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE:
                    tls_cipher_suite = p.value
        except Exception:
            LOG.warning("Failed to read TLS service parameters, "
                        "using defaults")

        go_tls_version = GO_TLS_VERSION_MAP.get(tls_min_version, 'tls1.2')

        # Docker Registry uses IANA cipher names directly
        cipher_list = [c.strip() for c in tls_cipher_suite.split(',')
                       if c.strip()]

        return {
            'platform::dockerdistribution::params::tls_min_version':
                go_tls_version,
            'platform::dockerdistribution::params::tls_cipher_suites':
                cipher_list,
        }

    def get_secure_system_config(self):
        registry_credentials = utils.get_local_docker_registry_auth()
        config = {
            'platform::dockerdistribution::params::registry_username': registry_credentials['username'],
            'platform::dockerdistribution::params::registry_password': registry_credentials['password']
        }

        return config
