#
# Copyright (c) 2017-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import os

from sysinv.common import constants
from sysinv.common import utils
from sysinv.openstack.common import log as logging

from sysinv.puppet import openstack

LOG = logging.getLogger(__name__)

# This section is for [DEFAULT] config params that may need to be applied
SP_CINDER_DEFAULT = constants.SERVICE_PARAM_SECTION_CINDER_DEFAULT
SP_CINDER_DEFAULT_PREFIX = 'openstack::cinder::config::default'
SP_CINDER_DEFAULT_ALL_SUPPORTED_PARAMS = [
    constants.SERVICE_PARAM_CINDER_DEFAULT_VOLUME_TYPE,
    constants.SERVICE_PARAM_CINDER_DEFAULT_MULTIPATH,
    # Hardcoded params: params we always want set
]

# This section is for [emc_vnx] config params that may need to be applied
SP_CINDER_EMC_VNX = constants.SERVICE_PARAM_SECTION_CINDER_EMC_VNX
SP_CINDER_EMC_VNX_PREFIX = 'openstack::cinder::emc_vnx'

# The entries in CINDER_EMC_VNX_PARAMETER_REQUIRED_ON_FEATURE_ENABLED,
# CINDER_EMC_VNX_PARAMETER_PROTECTED, and
# CINDER_EMC_VNX_PARAMETER_OPTIONAL in service_parameter.py
# in sysinv package must be in the following list.
SP_CINDER_EMC_VNX_ALL_SUPPORTED_PARAMS = [
    # From CINDER_EMC_VNX_PARAMETER_REQUIRED_ON_FEATURE_ENABLED
    'san_ip',
    # From CINDER_EMC_VNX_PARAMETER_PROTECTED list
    'san_login', 'san_password',
    # From CINDER_EMC_VNX_PARAMETER_OPTIONAL list
    'storage_vnx_pool_names', 'storage_vnx_security_file_dir',
    'san_secondary_ip', 'iscsi_initiators',
    'storage_vnx_authentication_type', 'initiator_auto_deregistration',
    'default_timeout', 'ignore_pool_full_threshold',
    'max_luns_per_storage_group', 'destroy_empty_storage_group',
    'force_delete_lun_in_storagegroup', 'io_port_list',
    'check_max_pool_luns_threshold',
    # Hardcoded params
    'volume_backend_name', 'volume_driver', 'naviseccli_path', 'storage_protocol',
    'initiator_auto_registration'
]

SP_CINDER_EMC_VNX_ALL_BLACKLIST_PARAMS = [
    'control_network', 'data_network', 'data_san_ip',
]

# This section is for [hpe3par] config params that may need to be applied
SP_CINDER_HPE3PAR = constants.SERVICE_PARAM_SECTION_CINDER_HPE3PAR
SP_CINDER_HPE3PAR_PREFIX = 'openstack::cinder::hpe3par'
SP_CINDER_HPE3PAR_ALL_SUPPORTED_PARAMS = [
    'hpe3par_api_url', 'hpe3par_username', 'hpe3par_password',
    'hpe3par_cpg', 'hpe3par_cpg_snap', 'hpe3par_snapshot_expiration',
    'hpe3par_debug', 'hpe3par_iscsi_ips', 'hpe3par_iscsi_chap_enabled',
    'san_login', 'san_password', 'san_ip',
    # Hardcoded params
    'volume_backend_name', 'volume_driver'
]

# This section is for [hpelefthand] config params that may need to be applied
SP_CINDER_HPELEFTHAND = constants.SERVICE_PARAM_SECTION_CINDER_HPELEFTHAND
SP_CINDER_HPELEFTHAND_PREFIX = 'openstack::cinder::hpelefthand'
SP_CINDER_HPELEFTHAND_ALL_SUPPORTED_PARAMS = [
    'hpelefthand_api_url', 'hpelefthand_username', 'hpelefthand_password',
    'hpelefthand_clustername', 'hpelefthand_debug', 'hpelefthand_ssh_port',
    'hpelefthand_iscsi_chap_enabled',
    # Hardcoded params
    'volume_backend_name', 'volume_driver'
]

SP_CONF_NAME_KEY = 'conf_name'
SP_PARAM_PROCESS_KEY = 'param_process'
SP_POST_PROCESS_KEY = 'post_process'
SP_PROVIDED_PARAMS_LIST_KEY = 'provided_params_list'
SP_ABSENT_PARAMS_LIST_KEY = 'absent_params_list'


#
# common section processing calls
#


def sp_common_param_process(config, section, section_map, name, value):
    if SP_PROVIDED_PARAMS_LIST_KEY not in section_map:
        section_map[SP_PROVIDED_PARAMS_LIST_KEY] = {}
    section_map[SP_PROVIDED_PARAMS_LIST_KEY][name] = value


def sp_common_post_process(config, section, section_map, is_service_enabled,
                           enabled_backends, is_a_feature=True):
    if section_map:
        provided_params = section_map.get(SP_PROVIDED_PARAMS_LIST_KEY, {})
        absent_params = section_map.get(SP_ABSENT_PARAMS_LIST_KEY, [])

        conf_name = section_map.get(SP_CONF_NAME_KEY) + '::config_params'

        if is_a_feature:
            feature_enabled_conf = section_map.get(SP_CONF_NAME_KEY) + '::feature_enabled'

            # Convert "enabled" service param to 'feature_enabled' param
            config[feature_enabled_conf] = provided_params.get('enabled', 'false').lower()
            if 'enabled' in provided_params:
                del provided_params['enabled']

            # Inform Cinder to support this storage backend as well
            if config[feature_enabled_conf] == 'true':
                enabled_backends.append(section)

        # Reformat the params data structure to match with puppet config
        # resource.  This will make puppet code very simple. For example
        # default Hiera file defaults.yaml has the followings for emc_vnx
        #
        # openstack::cinder::emc_vnx::featured_enabled: 'true'
        # openstack::cinder::emc_vnx::config_params:
        #    emc_vnx/san_login:
        #        value: sysadmin
        #    emc_vnx/san_ip:
        #        value: 1.2.3.4
        #    emc_vnx/default_timeout:
        #        value: 120
        #    emc_vnx/san_secondary_ip:
        #        ensure: absent
        #
        # With this format, Puppet only needs to do this:
        #    create_resources('cinder_config', hiera_hash(
        #        '', {}))

        provided_params_puppet_format = {}
        for param, value in provided_params.items():
            provided_params_puppet_format[section + '/' + param] = {
                'value': value
            }
        for param in absent_params:
            # 'ensure': 'absent' makes sure this param will be removed
            # out of cinder.conf
            provided_params_puppet_format[section + '/' + param] = {
                'ensure': 'absent'
            }

        config[conf_name] = provided_params_puppet_format


#
# Section specific post processing calls: DEFAULT, emc_vnx, hpe3par, hpelefthand
#
def sp_multipath_post_process(config, provided_params):
    #   DEFAULT/multipath does not map 1:1 to an entry in cinder.conf
    param = constants.SERVICE_PARAM_CINDER_DEFAULT_MULTIPATH
    multipath_key = 'platform::multipath::params::enabled'
    if provided_params.get(param, 'false').lower() == 'true':
        config[multipath_key] = True
    else:
        config.pop(multipath_key, None)
    provided_params.pop(param, None)
    param_state = constants.SERVICE_PARAM_CINDER_DEFAULT_MULTIPATH_STATE
    provided_params.pop(param_state, None)


def sp_default_post_process(config, section, section_map,
                            is_service_enabled, enabled_backends):

    provided_params = section_map.get(SP_PROVIDED_PARAMS_LIST_KEY, {})

    if not is_service_enabled:
        # If the service is not enabled and there are some provided params then
        # just remove all of these params as they should not be in cinder.conf
        section_map[SP_PROVIDED_PARAMS_LIST_KEY] = {}
        provided_params = section_map[SP_PROVIDED_PARAMS_LIST_KEY]
    else:
        # Special Handling:

        # SERVICE_PARAM_CINDER_DEFAULT_VOLUME_TYPE:
        #   Ceph tiers: Since we may have multiple ceph backends, prioritize the
        #   primary backend to maintain existing behavior if a default volume
        #   type is not set
        param = constants.SERVICE_PARAM_CINDER_DEFAULT_VOLUME_TYPE
        if param not in provided_params:
            if constants.CINDER_BACKEND_CEPH in enabled_backends:
                provided_params[param] = constants.CINDER_BACKEND_CEPH

    # Now make sure the parameters which are not in the provided_params list are
    # removed out of cinder.conf
    absent_params = section_map[SP_ABSENT_PARAMS_LIST_KEY] = []
    for param in SP_CINDER_DEFAULT_ALL_SUPPORTED_PARAMS:
        if param not in provided_params:
            absent_params.append(param)

    sp_multipath_post_process(config, provided_params)

    sp_common_post_process(config, section, section_map, is_service_enabled,
                           enabled_backends, is_a_feature=False)


def sp_emc_vnx_post_process(config, section, section_map,
                            is_service_enabled, enabled_backends):
    provided_params = section_map.get(SP_PROVIDED_PARAMS_LIST_KEY, {})

    if provided_params.get('enabled', 'false').lower() == 'true':
        # Supply some required parameter with default values
        if 'storage_vnx_pool_names' not in provided_params:
            provided_params['storage_vnx_pool_names'] = 'TiS_Pool'
        if 'san_ip' not in provided_params:
            provided_params['san_ip'] = ''

        # if storage_vnx_security_file_dir provided than following params
        # san_login, san_password, storage_vnx_authentication_type will be
        # removed.
        if 'storage_vnx_security_file_dir' not in provided_params:
            if 'san_login' not in provided_params:
                provided_params['san_login'] = 'sysadmin'
            if 'san_password' not in provided_params:
                provided_params['san_password'] = 'sysadmin'
        else:
            if 'san_login' in provided_params:
                del provided_params['san_login']
            if 'san_password' in provided_params:
                del provided_params['san_password']
            if 'storage_vnx_authentication_type' in provided_params:
                del provided_params['storage_vnx_authentication_type']

        if 'force_delete_lun_in_storagegroup' not in provided_params:
            provided_params['force_delete_lun_in_storagegroup'] = 'True'

        # Hardcoded params must exist in cinder.conf.
        provided_params['volume_backend_name'] = SP_CINDER_EMC_VNX
        provided_params['volume_driver'] = (
            'cinder.volume.drivers.emc.vnx.driver.EMCVNXDriver')
        provided_params['storage_protocol'] = 'iscsi'
        provided_params['naviseccli_path'] = '/opt/Navisphere/bin/naviseccli'
        provided_params['initiator_auto_registration'] = 'True'

        for param in SP_CINDER_EMC_VNX_ALL_BLACKLIST_PARAMS:
            if param in provided_params:
                del provided_params[param]
    else:
        # If the feature is not enabled and there are some provided params
        # then just remove all of these params as they should not be in the
        # cinder.conf
        section_map[SP_PROVIDED_PARAMS_LIST_KEY] = {}
        provided_params = section_map[SP_PROVIDED_PARAMS_LIST_KEY]

    # Now make sure the parameters which are not in the provided_params list are
    # removed out of cinder.conf
    absent_params = section_map[SP_ABSENT_PARAMS_LIST_KEY] = []
    for param in SP_CINDER_EMC_VNX_ALL_SUPPORTED_PARAMS:
        if param not in provided_params:
            absent_params.append(param)

    sp_common_post_process(config, section, section_map, is_service_enabled,
                           enabled_backends)


def sp_hpe3par_post_process(config, section, section_map,
                            is_service_enabled, enabled_backends):

    provided_params = section_map.get(SP_PROVIDED_PARAMS_LIST_KEY, {})

    if provided_params.get('enabled', 'false').lower() == 'true':
        # Hardcoded params must exist in cinder.conf.
        provided_params['volume_backend_name'] = section
        provided_params['volume_driver'] = (
            'cinder.volume.drivers.hpe.hpe_3par_iscsi.HPE3PARISCSIDriver')

    else:
        # If the feature is not enabled and there are some provided params
        # then just remove all of these params as they should not be in the
        # cinder.conf
        section_map[SP_PROVIDED_PARAMS_LIST_KEY] = {}
        provided_params = section_map[SP_PROVIDED_PARAMS_LIST_KEY]

    # Now make sure the parameters which are not in the provided_params list are
    # removed out of cinder.conf
    absent_params = section_map[SP_ABSENT_PARAMS_LIST_KEY] = []
    for param in SP_CINDER_HPE3PAR_ALL_SUPPORTED_PARAMS:
        if param not in provided_params:
            absent_params.append(param)

    sp_common_post_process(config, section, section_map, is_service_enabled,
                           enabled_backends)


def sp_hpelefthand_post_process(config, section, section_map,
                                is_service_enabled, enabled_backends):

    provided_params = section_map.get(SP_PROVIDED_PARAMS_LIST_KEY, {})

    if provided_params.get('enabled', 'false').lower() == 'true':
        # Hardcoded params must exist in cinder.conf.
        provided_params['volume_backend_name'] = SP_CINDER_HPELEFTHAND
        provided_params['volume_driver'] = (
            'cinder.volume.drivers.hpe.hpe_lefthand_iscsi.HPELeftHandISCSIDriver')

    else:
        # If the feature is not enabled and there are some provided params
        # then just remove all of these params as they should not be in the
        # cinder.conf
        section_map[SP_PROVIDED_PARAMS_LIST_KEY] = {}
        provided_params = section_map[SP_PROVIDED_PARAMS_LIST_KEY]

    # Now make sure the parameters which are not in the provided_params list are
    # removed out of cinder.conf
    absent_params = section_map[SP_ABSENT_PARAMS_LIST_KEY] = []
    for param in SP_CINDER_HPELEFTHAND_ALL_SUPPORTED_PARAMS:
        if param not in provided_params:
            absent_params.append(param)

    sp_common_post_process(config, section, section_map, is_service_enabled,
                           enabled_backends)


# For each section provided is:
#   SP_CONF_NAME_KEY    : The hieradata path for this section
#   SP_PARAM_PROCESS_KEY: This function is invoked for every service param
#                         belonging to the section
#   SP_POST_PROCESS_KEY : This function is invoked after each individual service
#                          param in the section is processed
SP_CINDER_SECTION_MAPPING = {
    SP_CINDER_DEFAULT: {
        SP_CONF_NAME_KEY: SP_CINDER_DEFAULT_PREFIX,
        SP_PARAM_PROCESS_KEY: sp_common_param_process,
        SP_POST_PROCESS_KEY: sp_default_post_process,
    },

    SP_CINDER_EMC_VNX: {
        SP_CONF_NAME_KEY: SP_CINDER_EMC_VNX_PREFIX,
        SP_PARAM_PROCESS_KEY: sp_common_param_process,
        SP_POST_PROCESS_KEY: sp_emc_vnx_post_process,
    },

    SP_CINDER_HPE3PAR: {
        SP_CONF_NAME_KEY: SP_CINDER_HPE3PAR_PREFIX,
        SP_PARAM_PROCESS_KEY: sp_common_param_process,
        SP_POST_PROCESS_KEY: sp_hpe3par_post_process,
    },

    SP_CINDER_HPELEFTHAND: {
        SP_CONF_NAME_KEY: SP_CINDER_HPELEFTHAND_PREFIX,
        SP_PARAM_PROCESS_KEY: sp_common_param_process,
        SP_POST_PROCESS_KEY: sp_hpelefthand_post_process,
    },
}


class CinderPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for cinder configuration"""

    SERVICE_NAME = 'cinder'
    SERVICE_TYPE = 'volume'
    SERVICE_PORT = 8776
    SERVICE_PATH_V1 = 'v1/%(tenant_id)s'
    SERVICE_PATH_V2 = 'v2/%(tenant_id)s'
    SERVICE_PATH_V3 = 'v3/%(tenant_id)s'
    PROXY_SERVICE_PORT = '28776'

    def __init__(self, *args, **kwargs):
        super(CinderPuppet, self).__init__(*args, **kwargs)
        # Update the section mapping for multiple HPE3PAR backends
        for i in range(2, constants.SERVICE_PARAM_MAX_HPE3PAR + 1):
            section = "{0}{1}".format(SP_CINDER_HPE3PAR, i)
            prefix = "{0}{1}".format(SP_CINDER_HPE3PAR_PREFIX, i)
            SP_CINDER_SECTION_MAPPING[section] = {
                SP_CONF_NAME_KEY: prefix,
                SP_PARAM_PROCESS_KEY: sp_common_param_process,
                SP_POST_PROCESS_KEY: sp_hpe3par_post_process,
            }

    def get_static_config(self):
        dbuser = self._get_database_username(self.SERVICE_NAME)

        return {
            'cinder::db::postgresql::user': dbuser,
        }

    def get_secure_static_config(self):
        dbpass = self._get_database_password(self.SERVICE_NAME)
        kspass = self._get_service_password(self.SERVICE_NAME)

        return {
            'cinder::db::postgresql::password': dbpass,

            'cinder::keystone::auth::password': kspass,
            'cinder::keystone::authtoken::password': kspass,
        }

    def get_system_config(self):
        config_ksuser = True
        ksuser = self._get_service_user_name(self.SERVICE_NAME)
        service_config = None
        # If we are in Region config and Cinder is a shared service
        # then don't configure an account for Cinder
        if self._region_config():
            if self.SERVICE_TYPE in self._get_shared_services():
                service_config = self._get_service_config(self.SERVICE_NAME)
                config_ksuser = False
            else:
                ksuser += self._region_name()

        config = {
            'cinder::api::os_region_name': self._keystone_region_name(),

            'cinder::keystone::auth::configure_user': config_ksuser,
            'cinder::keystone::auth::public_url':
                self.get_public_url('cinder_public_uri_v1', service_config),
            'cinder::keystone::auth::internal_url':
                self.get_internal_url('cinder_internal_uri_v1', service_config),
            'cinder::keystone::auth::admin_url':
                self.get_admin_url('cinder_admin_uri_v1', service_config),
            'cinder::keystone::auth::region':
                self._region_name(),
            'cinder::keystone::auth::auth_name': ksuser,
            'cinder::keystone::auth::tenant':
                self._get_service_tenant_name(),

            'cinder::keystone::auth::public_url_v2':
                self.get_public_url('cinder_public_uri_v2', service_config),
            'cinder::keystone::auth::internal_url_v2':
                self.get_internal_url('cinder_internal_uri_v2', service_config),
            'cinder::keystone::auth::admin_url_v2':
                self.get_admin_url('cinder_admin_uri_v2', service_config),

            'cinder::keystone::auth::public_url_v3':
                self.get_public_url('cinder_public_uri_v3', service_config),
            'cinder::keystone::auth::internal_url_v3':
                self.get_internal_url('cinder_internal_uri_v3', service_config),
            'cinder::keystone::auth::admin_url_v3':
                self.get_admin_url('cinder_admin_uri_v3', service_config),

            'cinder::keystone::auth::dc_region':
                constants.SYSTEM_CONTROLLER_REGION,
            'cinder::keystone::auth::proxy_v2_public_url':
                self.get_proxy_public_url('v2'),
            'cinder::keystone::auth::proxy_v3_public_url':
                self.get_proxy_public_url('v3'),
            'cinder::keystone::auth::proxy_v2_admin_url':
                self.get_proxy_admin_url('v2'),
            'cinder::keystone::auth::proxy_v3_admin_url':
                self.get_proxy_admin_url('v3'),
            'cinder::keystone::auth::proxy_v2_internal_url':
                self.get_proxy_internal_url('v2'),
            'cinder::keystone::auth::proxy_v3_internal_url':
                self.get_proxy_internal_url('v3'),

            'cinder::keystone::authtoken::region_name':
                self._keystone_region_name(),
            'cinder::keystone::authtoken::auth_url':
                self._keystone_identity_uri(),
            'cinder::keystone::authtoken::auth_uri':
                self._keystone_auth_uri(),
            'cinder::keystone::authtoken::user_domain_name':
                self._get_service_user_domain_name(),
            'cinder::keystone::authtoken::project_domain_name':
                self._get_service_project_domain_name(),
            'cinder::keystone::authtoken::project_name':
                self._get_service_tenant_name(),
            'cinder::keystone::authtoken::username': ksuser,

            'cinder::glance::glance_api_servers':
                self._operator.glance.get_glance_url(),

            'openstack::cinder::params::region_name':
                self.get_region_name(),
            'openstack::cinder::params::service_type':
                self.get_service_type(),
            'openstack::cinder::params::service_type_v2':
                self.get_service_type_v2(),
            'openstack::cinder::params::service_type_v3':
                self.get_service_type_v3(),
        }

        # no need to configure cinder endpoints as the proxy provides
        # the endpoints in SystemController
        if (self._distributed_cloud_role() ==
                constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER):
            config.update({
                'cinder::keystone::auth::configure_endpoint': False,
                'cinder::keystone::auth::configure_endpoint_v2': False,
                'cinder::keystone::auth::configure_endpoint_v3': False,
                'openstack::cinder::params::configure_endpoint': False,
            })

        enabled_backends = []
        ceph_backend_configs = {}
        ceph_type_configs = {}

        is_service_enabled = False
        is_ceph_external = False
        for storage_backend in self.dbapi.storage_backend_get_list():
            if (storage_backend.backend == constants.SB_TYPE_LVM and
                (storage_backend.services and
                 constants.SB_SVC_CINDER in storage_backend.services)):
                is_service_enabled = True
                enabled_backends.append(storage_backend.backend)

                lvm_type = constants.CINDER_LVM_TYPE_THIN
                lvgs = self.dbapi.ilvg_get_all()
                for vg in lvgs:
                    if vg.lvm_vg_name == constants.LVG_CINDER_VOLUMES:
                        lvm_type = vg.capabilities.get('lvm_type')
                        if lvm_type == constants.CINDER_LVM_TYPE_THICK:
                            lvm_type = 'default'

                config.update({
                    'openstack::cinder::lvm::lvm_type': lvm_type,

                    'openstack::cinder::params::cinder_address':
                        self._get_cinder_address(),

                    'openstack::cinder::params::iscsi_ip_address':
                        self._format_url_address(self._get_cinder_address()),

                    # TODO (rchurch): Re-visit this logic to make sure that this
                    # information is not stale in the manifest when applied
                    'openstack::cinder::lvm::filesystem::drbd::drbd_handoff':
                        not utils.is_single_controller(self.dbapi),
                })
            elif storage_backend.backend == constants.SB_TYPE_CEPH:
                ceph_obj = self.dbapi.storage_ceph_get(storage_backend.id)
                ceph_backend = {
                    'backend_enabled': False,
                    'backend_name': constants.CINDER_BACKEND_CEPH,
                    'rbd_pool': constants.CEPH_POOL_VOLUMES_NAME
                }
                ceph_backend_type = {
                    'type_enabled': False,
                    'type_name': constants.CINDER_BACKEND_CEPH,
                    'backend_name': constants.CINDER_BACKEND_CEPH
                }

                if (ceph_obj.tier_name != constants.SB_TIER_DEFAULT_NAMES[
                        constants.SB_TIER_TYPE_CEPH]):
                    tier_vol_backend = "{0}-{1}".format(
                        ceph_backend['backend_name'],
                        ceph_obj.tier_name)
                    ceph_backend['backend_name'] = tier_vol_backend
                    ceph_backend_type['backend_name'] = tier_vol_backend

                    ceph_backend['rbd_pool'] = "{0}-{1}".format(
                        ceph_backend['rbd_pool'], ceph_obj.tier_name)

                    ceph_backend_type['type_name'] = "{0}-{1}".format(
                        ceph_backend_type['type_name'],
                        ceph_obj.tier_name)

                if (storage_backend.services and
                        constants.SB_SVC_CINDER in storage_backend.services):
                    is_service_enabled = True
                    ceph_backend['backend_enabled'] = True
                    ceph_backend_type['type_enabled'] = True
                    enabled_backends.append(ceph_backend['backend_name'])

                ceph_backend_configs.update({storage_backend.name: ceph_backend})
                ceph_type_configs.update({storage_backend.name: ceph_backend_type})
            elif storage_backend.backend == constants.SB_TYPE_CEPH_EXTERNAL:
                is_ceph_external = True
                ceph_ext_obj = self.dbapi.storage_ceph_external_get(
                    storage_backend.id)
                ceph_external_backend = {
                    'backend_enabled': False,
                    'backend_name': ceph_ext_obj.name,
                    'rbd_pool':
                        storage_backend.capabilities.get('cinder_pool'),
                    'rbd_ceph_conf': constants.CEPH_CONF_PATH + os.path.basename(ceph_ext_obj.ceph_conf),
                }
                ceph_external_backend_type = {
                    'type_enabled': False,
                    'type_name': "{0}-{1}".format(
                        ceph_ext_obj.name,
                        constants.CINDER_BACKEND_CEPH_EXTERNAL),
                    'backend_name': ceph_ext_obj.name
                }

                if (storage_backend.services and
                        constants.SB_SVC_CINDER in storage_backend.services):
                    is_service_enabled = True
                    ceph_external_backend['backend_enabled'] = True
                    ceph_external_backend_type['type_enabled'] = True
                    enabled_backends.append(
                        ceph_external_backend['backend_name'])

                ceph_backend_configs.update(
                    {storage_backend.name: ceph_external_backend})
                ceph_type_configs.update(
                    {storage_backend.name: ceph_external_backend_type})

        # Update the params for the external SANs
        config.update(self._get_service_parameter_config(is_service_enabled,
                                                         enabled_backends))

        # Disable cinder services if kubernetes is enabled
        if self._kubernetes_enabled():
            is_service_enabled = False

        config.update({
            'openstack::cinder::params::service_enabled': is_service_enabled,
            'openstack::cinder::params::enabled_backends': enabled_backends,
            'openstack::cinder::params::is_ceph_external': is_ceph_external,
            'openstack::cinder::backends::ceph::ceph_backend_configs':
                ceph_backend_configs,
            'openstack::cinder::api::backends::ceph_type_configs':
                ceph_type_configs,
        })

        return config

    def get_secure_system_config(self):
        config = {
            'cinder::database_connection':
                self._format_database_connection(self.SERVICE_NAME),
        }

        return config

    def get_host_config(self, host):
        if (constants.CONTROLLER not in utils.get_personalities(host)):
            return {}

        cinder_device, cinder_size_gib = utils._get_cinder_device_info(self.dbapi, host.id)
        config = {}
        if cinder_device:
            config.update({
                'openstack::cinder::params::cinder_device': cinder_device,
                'openstack::cinder::params::cinder_size': cinder_size_gib
            })
        return config

    def get_public_url(self, version, service_config=None):
        if service_config is not None:
            url = service_config.capabilities.get(version, None)
            if url is not None:
                return url
        if version == 'cinder_public_uri_v1':
            return self._format_public_endpoint(self.SERVICE_PORT,
                                            path=self.SERVICE_PATH_V1)
        elif version == 'cinder_public_uri_v2':
            return self._format_public_endpoint(self.SERVICE_PORT,
                                            path=self.SERVICE_PATH_V2)
        elif version == 'cinder_public_uri_v3':
            return self._format_public_endpoint(self.SERVICE_PORT,
                                            path=self.SERVICE_PATH_V3)
        else:
            return None

    def get_internal_url(self, version, service_config=None):
        if service_config is not None:
            url = service_config.capabilities.get(version, None)
            if url is not None:
                return url
        if version == 'cinder_internal_uri_v1':
            return self._format_private_endpoint(self.SERVICE_PORT,
                                            path=self.SERVICE_PATH_V1)
        elif version == 'cinder_internal_uri_v2':
            return self._format_private_endpoint(self.SERVICE_PORT,
                                            path=self.SERVICE_PATH_V2)
        elif version == 'cinder_internal_uri_v3':
            return self._format_private_endpoint(self.SERVICE_PORT,
                                            path=self.SERVICE_PATH_V3)
        else:
            return None

    def get_admin_url(self, version, service_config=None):
        if service_config is not None:
            url = service_config.capabilities.get(version, None)
            if url is not None:
                return url
        if version == 'cinder_admin_uri_v1':
            return self._format_private_endpoint(self.SERVICE_PORT,
                                            path=self.SERVICE_PATH_V1)
        elif version == 'cinder_admin_uri_v2':
            return self._format_private_endpoint(self.SERVICE_PORT,
                                            path=self.SERVICE_PATH_V2)
        elif version == 'cinder_admin_uri_v3':
            return self._format_private_endpoint(self.SERVICE_PORT,
                                            path=self.SERVICE_PATH_V3)
        else:
            return None

    # proxies need public defined but should never use public endpoints
    def get_proxy_public_url(self, version):
        if version == 'v2':
            return self._format_private_endpoint(self.PROXY_SERVICE_PORT,
                                            path=self.SERVICE_PATH_V2)
        elif version == 'v3':
            return self._format_private_endpoint(self.PROXY_SERVICE_PORT,
                                            path=self.SERVICE_PATH_V3)
        else:
            return None

    def get_proxy_internal_url(self, version):
        if version == 'v2':
            return self._format_private_endpoint(self.PROXY_SERVICE_PORT,
                                            path=self.SERVICE_PATH_V2)
        elif version == 'v3':
            return self._format_private_endpoint(self.PROXY_SERVICE_PORT,
                                            path=self.SERVICE_PATH_V3)
        else:
            return None

    def get_proxy_admin_url(self, version):
        if version == 'v2':
            return self._format_private_endpoint(self.PROXY_SERVICE_PORT,
                                            path=self.SERVICE_PATH_V2)
        elif version == 'v3':
            return self._format_private_endpoint(self.PROXY_SERVICE_PORT,
                                            path=self.SERVICE_PATH_V3)
        else:
            return None

    def get_region_name(self):
        return self._get_service_region_name(self.SERVICE_NAME)

    def _get_neutron_url(self):
        return self._operator.neutron.get_internal_url()

    def _get_cinder_address(self):
        # obtain management network NFS address
        return self._get_address_by_name(
            constants.CONTROLLER_CINDER,
            constants.NETWORK_TYPE_MGMT).address

    def get_service_name(self):
        return self._get_configured_service_name(self.SERVICE_NAME)

    def get_service_type(self):
        service_type = self._get_configured_service_type(self.SERVICE_NAME)
        if service_type is None:
            return self.SERVICE_TYPE
        else:
            return service_type

    def get_service_name_v2(self):
        return self._get_configured_service_name(self.SERVICE_NAME, 'v2')

    def get_service_type_v2(self):
        service_type = self._get_configured_service_type(
            self.SERVICE_NAME, 'v2')
        if service_type is None:
            return self.SERVICE_TYPE + 'v2'
        else:
            return service_type

    def get_service_type_v3(self):
        service_type = self._get_configured_service_type(
            self.SERVICE_NAME, 'v3')
        if service_type is None:
            return self.SERVICE_TYPE + 'v3'
        else:
            return service_type

    def _get_service_parameter_config(self, is_service_enabled,
                                      enabled_backends):
        config = {}
        service_parameters = self._get_service_parameter_configs(
            constants.SERVICE_TYPE_CINDER)

        if service_parameters is None:
            return {}

        # DEFAULT section may or may not be present therefore reset param list
        SP_CINDER_SECTION_MAPPING[
            SP_CINDER_DEFAULT][SP_PROVIDED_PARAMS_LIST_KEY] = {}

        # Eval all currently provided parameters
        for s in service_parameters:
            if s.section in SP_CINDER_SECTION_MAPPING:
                SP_CINDER_SECTION_MAPPING[s.section].get(
                    SP_PARAM_PROCESS_KEY, sp_common_param_process)(
                        config, s.section,
                        SP_CINDER_SECTION_MAPPING[s.section],
                        s.name, s.value)

        for section, sp_section_map in SP_CINDER_SECTION_MAPPING.items():
            sp_section_map.get(SP_POST_PROCESS_KEY, sp_common_post_process)(
                config, section, sp_section_map,
                is_service_enabled, enabled_backends)

        # Build the list of possible HPE3PAR backends
        possible_hpe3pars = [s for s in SP_CINDER_SECTION_MAPPING.keys()
                             if constants.SERVICE_PARAM_SECTION_CINDER_HPE3PAR in s]
        config.update({'openstack::cinder::backends::hpe3par::sections': possible_hpe3pars})
        return config

    def is_service_enabled(self):
        for storage_backend in self.dbapi.storage_backend_get_list():
            if (storage_backend.backend == constants.SB_TYPE_LVM and
                (storage_backend.services and
                 constants.SB_SVC_CINDER in storage_backend.services)):
                return True
            elif (storage_backend.backend == constants.SB_TYPE_CEPH and
                  (storage_backend.services and
                   constants.SB_SVC_CINDER in storage_backend.services)):
                return True
            elif (storage_backend.backend == constants.SB_TYPE_CEPH_EXTERNAL and
                  (storage_backend.services and
                   constants.SB_SVC_CINDER in storage_backend.services)):
                return True

        return False
