"""
Copyright (c) 2014-2025 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import io
import logging
import os
import six

from six.moves import configparser

SW_VERSION = ""
SW_VERSION_21_12 = "21.12"
SW_VERSION_22_06 = "22.06"
SW_VERSION_22_12 = "22.12"

nodetype = None
subfunctions = []
region_config = "no"
region_1_name = None
region_2_name = None
vswitch_type = None
management_interface = None
oam_interface = None
cluster_host_interface = None
sdn_enabled = "no"
host_uuid = None
install_uuid = None
system_type = None
system_mode = None
security_profile = None
distributed_cloud_role = None
security_feature = None
http_port = "8080"

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

    # In python3 configparser uses strict mode by default. It doesn't
    # agree duplicate keys, and will throw an error
    # In python2 the strict argument is missing
    # TODO(dvoicule): the logic branching here can be removed once # pylint: disable=fixme
    # https://bugs.launchpad.net/starlingx/+bug/1931529 is fixed, allowing
    # python3 parser to work in strict mode.
    if six.PY2:
        config = configparser.SafeConfigParser()
        config.readfp(ini_fp)  # pylint: disable=deprecated-method
    elif six.PY3:
        config = configparser.SafeConfigParser(strict=False)  # pylint: disable=unexpected-keyword-arg
        config.read_file(ini_fp)

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
    if six.PY2:
        config.readfp(ini_fp)  # pylint: disable=deprecated-method
    elif six.PY3:
        config.read_file(ini_fp)

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

        global cluster_host_interface
        if config.has_option('platform_conf', 'cluster_host_interface'):
            cluster_host_interface = str(config.get('platform_conf',
                                                    'cluster_host_interface'))
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

        global http_port
        if config.has_option('platform_conf', 'http_port'):
            http_port = str(config.get('platform_conf', 'http_port'))

    except configparser.Error:
        logging.exception("Failed to read platform.conf")
        return False


_load()

# Keep the following path and flag declarations in sync with the tsconfig
#    bash script.
#

# Platform configuration paths and files

VOLATILE_PATH = "/var/run"
VOLATILE_PXEBOOT_PATH = "/var/pxeboot"
PLATFORM_PATH = "/opt/platform"
CONFIG_PATH = PLATFORM_PATH + "/config/" + SW_VERSION + "/"
PUPPET_PATH = PLATFORM_PATH + "/puppet/" + SW_VERSION + "/"
ARMADA_PATH = PLATFORM_PATH + "/armada/" + SW_VERSION
HELM_OVERRIDES_PATH = PLATFORM_PATH + "/helm/" + SW_VERSION
KEYRING_PATH = PLATFORM_PATH + "/.keyring/" + SW_VERSION
DEPLOY_PATH = PLATFORM_PATH + "/deploy/" + SW_VERSION
ETCD_PATH = "/opt/etcd"
EXTENSION_PATH = "/opt/extension"
IMAGE_CONVERSION_PATH = "/opt/conversion"
PLATFORM_CEPH_CONF_PATH = CONFIG_PATH + 'ceph-config'
PLATFORM_BACKUP_PATH = '/opt/platform-backup'

# Controller configuration flags

# Set after the first application of controller manifests
INITIAL_CONTROLLER_CONFIG_COMPLETE = os.path.join(
    PLATFORM_CONF_PATH, ".initial_controller_config_complete")
# Set after initial K8s config is completed
INITIAL_K8S_CONFIG_COMPLETE = os.path.join(
    PLATFORM_CONF_PATH, ".initial_k8s_config_complete")
# Set after each application of controller manifests
VOLATILE_CONTROLLER_CONFIG_COMPLETE = os.path.join(
    VOLATILE_PATH, ".controller_config_complete")

# Set when mgmt network reconfiguration is executed after
# INITIAL_CONTROLLER_CONFIG_COMPLETE
MGMT_NETWORK_RECONFIGURATION_ONGOING = os.path.join(
    PLATFORM_CONF_PATH, ".mgmt_network_reconfiguration_ongoing")

# Set when host-unlock was executed and hieradata was updated
# with new MGMT IP RANGE.
MGMT_NETWORK_RECONFIGURATION_UNLOCK = os.path.join(
    PLATFORM_CONF_PATH, ".mgmt_network_reconfiguration_unlock")

# Set by controller_config script to inform the sysinv to update
# /opt/platform/config/<release>/hosts with new mgmt IPs
MGMT_NETWORK_RECONFIG_UPDATE_HOST_FILES = os.path.join(
    PLATFORM_CONF_PATH, ".mgmt_reconfig_update_hosts_file")

# Set in the upgrade script to not use FQDN during SW upgrade
# must be deleted after upgrade complete /abort
UPGRADE_DO_NOT_USE_FQDN = os.path.join(
    PLATFORM_CONF_PATH, ".upgrade_do_not_use_fqdn")

# Worker configuration flags

# Set after initial application of node manifest
INITIAL_CONFIG_COMPLETE_FLAG = os.path.join(
    PLATFORM_CONF_PATH, ".initial_config_complete")
# Set after the first application of worker manifests
INITIAL_WORKER_CONFIG_COMPLETE = os.path.join(
    PLATFORM_CONF_PATH, ".initial_worker_config_complete")
# Set after each application of worker manifests
VOLATILE_WORKER_CONFIG_COMPLETE = os.path.join(
    VOLATILE_PATH, ".worker_config_complete")

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
# Update/upgrade from legacy PTP configuration has been already run
# TODO(douglashenrique.koerich): remove it in a later release # pylint: disable=fixme
PTP_UPDATE_PARAMETERS_DONE = '.update_ptp_parameters_done'
PTP_UPDATE_PARAMETERS_FLAG = os.path.join(CONFIG_PATH,
                                          PTP_UPDATE_PARAMETERS_DONE)

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
# Set while a restore is running to skip wiping OSD data
SKIP_CEPH_OSD_WIPING = os.path.join(
    PLATFORM_CONF_PATH, '.skip_ceph_osds_wipe')
# Mark that restore_system was run on controller-0. Will be deleted
# once controller-0 is restored completely
RESTORE_SYSTEM_FLAG = os.path.join(
    CONFIG_PATH, '.restore_system')
