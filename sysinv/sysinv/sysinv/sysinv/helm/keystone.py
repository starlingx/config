#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from six.moves import configparser
import os

from sysinv.common import constants
from sysinv.common import exception
from sysinv.openstack.common import log as logging
from . import common
from . import openstack

LOG = logging.getLogger(__name__)


OPENSTACK_PASSWORD_RULES_FILE = '/etc/keystone/password-rules.conf'


class KeystoneHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the keystone chart"""

    CHART = constants.HELM_CHART_KEYSTONE
    SUPPORTED_NAMESPACES = [
        common.HELM_NS_OPENSTACK
    ]

    SERVICE_NAME = constants.HELM_CHART_KEYSTONE
    SERVICE_PATH = '/v3'

    DEFAULT_DOMAIN_NAME = 'default'

    @property
    def docker_repo_source(self):
        return common.DOCKER_SRC_STX

    @property
    def docker_repo_tag(self):
        return common.DOCKER_SRCS[self.docker_repo_source][common.IMG_TAG_KEY]

    def get_namespaces(self):
        return self.SUPPORTED_NAMESPACES

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_OPENSTACK: {
                'pod': self._get_pod_overrides(),
                'conf': self._get_conf_overrides(),
                'endpoints': self._get_endpoints_overrides(),
                'images': self._get_images_overrides(),
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides

    def _get_pod_overrides(self):
        overrides = {
            'replicas': {
                'api': self._num_controllers()
            }
        }
        if self.docker_repo_source != common.DOCKER_SRC_OSH:
            overrides.update({'user': {'keystone': {'uid': 0}}})
        return overrides

    def _get_images_overrides(self):
        heat_image = self._operator.chart_operators[
            constants.HELM_CHART_HEAT].docker_image
        return {
            'tags': {
                'bootstrap': heat_image,
                'db_drop': heat_image,
                'db_init': heat_image,
                'keystone_api': self.docker_image,
                'keystone_credential_rotate': self.docker_image,
                'keystone_credential_setup': self.docker_image,
                'keystone_db_sync': self.docker_image,
                'keystone_domain_manage': self.docker_image,
                'keystone_fernet_rotate': self.docker_image,
                'keystone_fernet_setup': self.docker_image,
                'ks_user': heat_image,
            }
        }

    def _get_conf_keystone_default_overrides(self):
        return {
            'max_token_size': 255,  # static controller.yaml => chart default
            'debug': False,  # static controller.yaml => chart default
            'use_syslog': True,  # static controller.yaml
            'syslog_log_facility': 'local2',  # static controller.yaml
            'log_file': '/dev/null',  # static controller.yaml
            # 'admin_token': self._generate_random_password(length=32)
        }

    def _get_conf_keystone_database_overrides(self):
        return {
            'idle_timeout': 60,  # static controller.yaml
            'max_pool_size': 1,  # static controller.yaml
            'max_overflow': 50,  # static controller.yaml
        }

    def _get_conf_keystone_oslo_middleware_overrides(self):
        return {
            'enable_proxy_headers_parsing': True  # static controller.yaml
        }

    def _get_conf_keystone_token_overrides(self):
        return {
            'provider': 'fernet'  # static controller.yaml => chart default
        }

    def _get_conf_keystone_identity_overrides(self):
        return {
            'driver': 'sql'  # static controller.yaml
        }

    def _get_conf_keystone_assignment_overrides(self):
        return {
            'driver': 'sql'  # static controller.yaml
        }

    @staticmethod
    def _extract_openstack_password_rules_from_file(
            rules_file, section="security_compliance"):
        try:
            config = configparser.RawConfigParser()
            parsed_config = config.read(rules_file)
            if not parsed_config:
                msg = ("Cannot parse rules file: %s" % rules_file)
                raise Exception(msg)
            if not config.has_section(section):
                msg = ("Required section '%s' not found in rules file" % section)
                raise Exception(msg)

            rules = config.items(section)
            if not rules:
                msg = ("section '%s' contains no configuration options" % section)
                raise Exception(msg)
            return dict(rules)
        except Exception:
            raise Exception("Failed to extract password rules from file")

    def _get_password_rule(self):
        password_rule = {}
        if os.path.isfile(OPENSTACK_PASSWORD_RULES_FILE):
            try:
                passwd_rules = \
                    KeystoneHelm._extract_openstack_password_rules_from_file(
                        OPENSTACK_PASSWORD_RULES_FILE)
                password_rule.update({
                    'unique_last_password_count':
                        int(passwd_rules['unique_last_password_count']),
                    'password_regex':
                        self.quoted_str(passwd_rules['password_regex']),
                    'password_regex_description':
                        self.quoted_str(
                            passwd_rules['password_regex_description'])
                })
            except Exception:
                pass
        return password_rule

    def _get_conf_keystone_security_compliance_overrides(self):
        overrides = {
            'unique_last_password_count': 2,  # static controller.yaml
            'password_regex': self.quoted_str('^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()<>{}+=_\\\[\]\-?|~`,.;:]).{7,}$'),
            'password_regex_description': self.quoted_str('Password must have a minimum length of 7 characters, and must contain at least 1 upper case, 1 lower case, 1 digit, and 1 special character'),
        }
        overrides.update(self._get_password_rule())
        return overrides

    def _get_conf_keystone_overrides(self):
        return {
            'DEFAULT': self._get_conf_keystone_default_overrides(),
            'database': self._get_conf_keystone_database_overrides(),
            'oslo_middleware': self._get_conf_keystone_oslo_middleware_overrides(),
            'token': self._get_conf_keystone_token_overrides(),
            'identity': self._get_conf_keystone_identity_overrides(),
            'assignment': self._get_conf_keystone_assignment_overrides(),
            'security_compliance': self._get_conf_keystone_security_compliance_overrides(),
        }

    def _get_conf_policy_overrides(self):
        return {
            "admin_required": "role:admin or is_admin:1",
            "service_role": "role:service",
            "service_or_admin": "rule:admin_required or rule:service_role",
            "owner": "user_id:%(user_id)s",
            "admin_or_owner": "rule:admin_required or rule:owner",
            "token_subject": "user_id:%(target.token.user_id)s",
            "admin_or_token_subject": "rule:admin_required or rule:token_subject",
            "service_admin_or_token_subject":
                "rule:service_or_admin or rule:token_subject",
            "protected_domains":
                "'heat':%(target.domain.name)s or 'magnum':%(target.domain.name)s",
            "protected_projects":
                "'admin':%(target.project.name)s or 'services':%(target.project.name)s",
            "protected_admins":
                "'admin':%(target.user.name)s or 'heat_admin':%(target.user.name)s"
                " or 'dcmanager':%(target.user.name)s",
            "protected_roles":
                "'admin':%(target.role.name)s or 'heat_admin':%(target.user.name)s",
            "protected_services": [
                ["'aodh':%(target.user.name)s"],
                ["'ceilometer':%(target.user.name)s"],
                ["'cinder':%(target.user.name)s"],
                ["'glance':%(target.user.name)s"],
                ["'heat':%(target.user.name)s"],
                ["'neutron':%(target.user.name)s"],
                ["'nova':%(target.user.name)s"],
                ["'patching':%(target.user.name)s"],
                ["'sysinv':%(target.user.name)s"],
                ["'mtce':%(target.user.name)s"],
                ["'magnum':%(target.user.name)s"],
                ["'murano':%(target.user.name)s"],
                ["'panko':%(target.user.name)s"],
                ["'gnocchi':%(target.user.name)s"]
            ],
            "identity:delete_service": "rule:admin_required and not rule:protected_services",
            "identity:delete_domain": "rule:admin_required and not rule:protected_domains",
            "identity:delete_project": "rule:admin_required and not rule:protected_projects",
            "identity:delete_user": "rule:admin_required and not (rule:protected_admins or rule:protected_services)",
            "identity:change_password": "rule:admin_or_owner and not rule:protected_services",
            "identity:delete_role": "rule:admin_required and not rule:protected_roles",
        }

    def _get_conf_overrides(self):
        return {
            'keystone': self._get_conf_keystone_overrides(),
            'policy': self._get_conf_policy_overrides()
        }

    def _region_config(self):
        # A wrapper over the Base region_config check.
        if (self._distributed_cloud_role() ==
                constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD):
            return False
        else:
            return super(KeystoneHelm, self)._region_config()

    def _get_endpoints_overrides(self):
        return {
            'identity': {
                'auth': self._get_endpoints_identity_overrides(
                    self.SERVICE_NAME, []),
            },
            'oslo_cache': {
                'auth': {
                    'memcached_secret_key':
                        self._get_common_password('auth_memcache_key')
                }
            },
            'oslo_db': {
                'auth': self._get_endpoints_oslo_db_overrides(
                    self.SERVICE_NAME, [self.SERVICE_NAME])
            },
            'oslo_messaging': {
                'auth': self._get_endpoints_oslo_messaging_overrides(
                    self.SERVICE_NAME, [self.SERVICE_NAME])
            },
        }

    def get_admin_user_name(self):
        if self._region_config():
            service_config = self._get_service_config(self.SERVICE_NAME)
            if service_config is not None:
                return service_config.capabilities.get('admin_user_name')
        return common.USER_ADMIN

    def get_admin_user_domain(self):
        if self._region_config():
            service_config = self._get_service_config(self.SERVICE_NAME)
            if service_config is not None:
                return service_config.capabilities.get('admin_user_domain')
        return self.DEFAULT_DOMAIN_NAME

    def get_admin_project_name(self):
        if self._region_config():
            service_config = self._get_service_config(self.SERVICE_NAME)
            if service_config is not None:
                return service_config.capabilities.get('admin_project_name')
        return common.USER_ADMIN

    def get_admin_project_domain(self):
        if self._region_config():
            service_config = self._get_service_config(self.SERVICE_NAME)
            if service_config is not None:
                return service_config.capabilities.get('admin_project_domain')
        return self.DEFAULT_DOMAIN_NAME
