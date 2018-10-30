"""
Copyright (c) 2014-2016 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import os
from six.moves import configparser
import io
import logging

SW_VERSION = ""
SW_VERSION_1610 = '16.10'
SW_VERSION_1706 = '17.06'
SW_VERSION_1803 = '18.03'

nodetype = None
subfunctions = []
region_config = "no"
region_1_name = None
region_2_name = None
vswitch_type = None
management_interface = None
oam_interface = None
infrastructure_interface = None
sdn_enabled = "no"
host_uuid = None
install_uuid = None
system_type = None
system_mode = None
security_profile = None
distributed_cloud_role = None
security_feature = None

PLATFORM_CONF_PATH = '/etc/platform'
PLATFORM_CONF_FILE = os.path.join(PLATFORM_CONF_PATH, 'platform.conf')
PLATFORM_SIMPLEX_FLAG = os.path.join(PLATFORM_CONF_PATH, 'simplex')

PUPPET_CONF_PATH = '/etc/puppet'


def _load():
    global SW_VERSION, nodetype, subfunctions
    # Read the build.info file
    build_info = '/etc/build.info'

    if not os.path.isfile(build_info):
        # Assume that we are in a test environment. Dirty, dirty, dirty...
        SW_VERSION = 'TEST.SW.VERSION'
        nodetype = 'controller'
        subfunctions = ['controller']
        return

    # The build.info file has no section headers, which causes problems
    # for ConfigParser. So we'll fake it out.
    ini_str = u'[build_info]\n' + open(build_info, 'r').read()
    ini_fp = io.StringIO(ini_str)

    config = configparser.SafeConfigParser()
    config.readfp(ini_fp)

    try:
        value = str(config.get('build_info', 'SW_VERSION'))

        SW_VERSION = value.strip('"')
    except configparser.Error:
        logging.exception("Failed to read SW_VERSION from /etc/build.info")
        return False

    # Read the platform.conf file

    # The platform.conf file has no section headers, which causes problems
    # for ConfigParser. So we'll fake it out.
    ini_str = u'[platform_conf]\n' + open(PLATFORM_CONF_FILE, 'r').read()
    ini_fp = io.StringIO(ini_str)
    config.readfp(ini_fp)

    try:
        value = str(config.get('platform_conf', 'nodetype'))

        nodetype = value

        value = str(config.get('platform_conf', 'subfunction'))

        subfunctions = value.split(",")

        global region_config
        if config.has_option('platform_conf', 'region_config'):
            region_config = str(config.get('platform_conf', 'region_config'))

        global region_1_name
        if config.has_option('platform_conf', 'region_1_name'):
            region_1_name = str(config.get('platform_conf', 'region_1_name'))

        global region_2_name
        if config.has_option('platform_conf', 'region_2_name'):
            region_2_name = str(config.get('platform_conf', 'region_2_name'))

        global vswitch_type
        if config.has_option('platform_conf', 'vswitch_type'):
            vswitch_type = str(config.get('platform_conf', 'vswitch_type'))

        global management_interface
        if config.has_option('platform_conf', 'management_interface'):
            management_interface = str(config.get('platform_conf',
                                       'management_interface'))

        global oam_interface
        if config.has_option('platform_conf', 'oam_interface'):
            oam_interface = str(config.get('platform_conf', 'oam_interface'))

        global infrastructure_interface
        if config.has_option('platform_conf', 'infrastructure_interface'):
            infrastructure_interface = str(config.get('platform_conf',
                                           'infrastructure_interface'))
        global sdn_enabled
        if config.has_option('platform_conf', 'sdn_enabled'):
            sdn_enabled = str(config.get('platform_conf', 'sdn_enabled'))

        global host_uuid
        if config.has_option('platform_conf', 'UUID'):
            host_uuid = str(config.get('platform_conf', 'UUID'))

        global install_uuid
        if config.has_option('platform_conf', 'INSTALL_UUID'):
            install_uuid = str(config.get('platform_conf', 'INSTALL_UUID'))

        global system_type
        if config.has_option('platform_conf', 'system_type'):
            system_type = str(config.get('platform_conf', 'system_type'))

        global system_mode
        if config.has_option('platform_conf', 'system_mode'):
            system_mode = str(config.get('platform_conf', 'system_mode'))

        global security_profile
        if config.has_option('platform_conf', 'security_profile'):
            security_profile = str(config.get('platform_conf',
                                   'security_profile'))

        global distributed_cloud_role
        if config.has_option('platform_conf', 'distributed_cloud_role'):
            distributed_cloud_role = str(config.get('platform_conf',
                                         'distributed_cloud_role'))

        global security_feature
        if config.has_option('platform_conf', 'security_feature'):
            security_feature = str(config.get('platform_conf', 'security_feature'))

    except configparser.Error:
        logging.exception("Failed to read platform.conf")
        return False


_load()

# Keep the following path and flag declarations in sync with the tsconfig
#    bash script.
#

# Platform configuration paths and files

VOLATILE_PATH = "/var/run"
PLATFORM_PATH = "/opt/platform"
CONFIG_PATH = PLATFORM_PATH + "/config/" + SW_VERSION + "/"
PUPPET_PATH = PLATFORM_PATH + "/puppet/" + SW_VERSION + "/"
CGCS_PATH = "/opt/cgcs"
KEYRING_PATH = PLATFORM_PATH + "/.keyring/" + SW_VERSION
EXTENSION_PATH = "/opt/extension"
PLATFORM_CEPH_CONF_PATH = CONFIG_PATH + 'ceph-config'

# Controller configuration flags

# Set after the first application of controller manifests
INITIAL_CONTROLLER_CONFIG_COMPLETE = os.path.join(
    PLATFORM_CONF_PATH, ".initial_controller_config_complete")
# Set after each application of controller manifests
VOLATILE_CONTROLLER_CONFIG_COMPLETE = os.path.join(
    VOLATILE_PATH, ".controller_config_complete")

# Compute configuration flags

# Set after initial application of node manifest
INITIAL_CONFIG_COMPLETE_FLAG = os.path.join(
    PLATFORM_CONF_PATH, ".initial_config_complete")
# Set after the first application of compute manifests
INITIAL_COMPUTE_CONFIG_COMPLETE = os.path.join(
    PLATFORM_CONF_PATH, ".initial_compute_config_complete")
# Set after each application of compute manifests
VOLATILE_COMPUTE_CONFIG_COMPLETE = os.path.join(
    VOLATILE_PATH, ".compute_config_complete")
# Set to prevent starting compute services (used in combined node upgrade)
VOLATILE_DISABLE_COMPUTE_SERVICES = os.path.join(
    VOLATILE_PATH, ".disable_compute_services")

# Storage configuration flags

# Set after the first application of storage manifests
INITIAL_STORAGE_CONFIG_COMPLETE = os.path.join(
    PLATFORM_CONF_PATH, ".initial_storage_config_complete")
# Set after each application of storage manifests
VOLATILE_STORAGE_CONFIG_COMPLETE = os.path.join(
    VOLATILE_PATH, ".storage_config_complete")

# Upgrade flags

# Set on controller-0 to force controller-1 to do an upgrade after install.
CONTROLLER_UPGRADE_FLAG = os.path.join(
    PLATFORM_CONF_PATH, '.upgrade_controller_1')
# Set on controller-0 (by controller-1) to indicate a completed upgrade.
CONTROLLER_UPGRADE_COMPLETE_FLAG = os.path.join(
    PLATFORM_CONF_PATH, '.upgrade_controller_1_complete')
# Set on controller-0 (by controller-1) to indicate a failed upgrade.
CONTROLLER_UPGRADE_FAIL_FLAG = os.path.join(
    PLATFORM_CONF_PATH, '.upgrade_controller_1_fail')
# Set on controller-1 to indicate we are rolling back the upgrade
UPGRADE_ROLLBACK_FLAG = os.path.join(
    PLATFORM_CONF_PATH, '.upgrade_rollback')
# Set on controller-1 to indicate we are aborting the upgrade
UPGRADE_ABORT_FILE = '.upgrade_abort'
UPGRADE_ABORT_FLAG = os.path.join(
    CONFIG_PATH, UPGRADE_ABORT_FILE)

# Set on controller-0 (by controller-1) to indicate that data migration has
# started
CONTROLLER_UPGRADE_STARTED_FLAG = os.path.join(
    PLATFORM_CONF_PATH, '.upgrade_controller_1_started')

# Backup / Restore flags
BACKUP_IN_PROGRESS_FLAG = os.path.join(
    PLATFORM_CONF_PATH, '.backup_in_progress')
# Set while a restore is running to prevent another restore being started
RESTORE_IN_PROGRESS_FLAG = os.path.join(
    PLATFORM_CONF_PATH, '.restore_in_progress')
# Mark that restore_system was run on controller-0. Will be deleted
# once controller-0 is restored completely
RESTORE_SYSTEM_FLAG = os.path.join(
    CONFIG_PATH, '.restore_system')
