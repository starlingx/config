"""
Copyright (c) 2015-2017 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

from __future__ import print_function
from six.moves import configparser
import os
import readline
import sys
import textwrap

from common import constants
from common import log
from common.exceptions import (BackupFail, RestoreFail, UserQuit, CloneFail)
from configutilities import lag_mode_to_str, Network, validate
from configutilities import ConfigFail
from configutilities import DEFAULT_CONFIG, REGION_CONFIG, SUBCLOUD_CONFIG
from configutilities import MGMT_TYPE, HP_NAMES, DEFAULT_NAMES
from configassistant import ConfigAssistant
import backup_restore
import utils
import clone

# Temporary file for building cgcs_config
TEMP_CGCS_CONFIG_FILE = "/tmp/cgcs_config"

LOG = log.get_logger(__name__)


def parse_system_config(config_file):
    """Parse system config file"""
    system_config = configparser.RawConfigParser()
    try:
        system_config.read(config_file)
    except Exception as e:
        LOG.exception(e)
        raise ConfigFail("Error parsing system config file")

    # Dump configuration for debugging
    # for section in config.sections():
    #    print "Section: %s" % section
    #    for (name, value) in config.items(section):
    #        print "name: %s, value: %s" % (name, value)
    return system_config


def configure_management_interface(region_config, config_type=REGION_CONFIG):
    """Bring up management interface
    """
    mgmt_network = Network()
    if region_config.has_section('CLM_NETWORK'):
        naming_type = HP_NAMES
    else:
        naming_type = DEFAULT_NAMES

    if config_type == SUBCLOUD_CONFIG:
        min_addresses = 5
    else:
        min_addresses = 8
    try:
        mgmt_network.parse_config(region_config, config_type, MGMT_TYPE,
                                  min_addresses=min_addresses,
                                  naming_type=naming_type)
    except ConfigFail:
        raise
    except Exception as e:
        LOG.exception("Error parsing configuration file")
        raise ConfigFail("Error parsing configuration file: %s" % e)

    try:
        # Remove interface config files currently installed
        utils.remove_interface_config_files()

        # Create the management interface configuration files.
        # Code based on ConfigAssistant._write_interface_config_management
        parameters = utils.get_interface_config_static(
            mgmt_network.start_address,
            mgmt_network.cidr,
            mgmt_network.gateway_address)

        if mgmt_network.logical_interface.lag_interface:
            management_interface = 'bond0'
        else:
            management_interface = mgmt_network.logical_interface.ports[0]

        if mgmt_network.vlan:
            management_interface_name = "%s.%s" % (management_interface,
                                                   mgmt_network.vlan)
            utils.write_interface_config_vlan(
                management_interface_name,
                mgmt_network.logical_interface.mtu,
                parameters)

            # underlying interface has no additional parameters
            parameters = None
        else:
            management_interface_name = management_interface

        if mgmt_network.logical_interface.lag_interface:
            utils.write_interface_config_bond(
                management_interface,
                mgmt_network.logical_interface.mtu,
                lag_mode_to_str(mgmt_network.logical_interface.lag_mode),
                None,
                constants.LAG_MIIMON_FREQUENCY,
                mgmt_network.logical_interface.ports[0],
                mgmt_network.logical_interface.ports[1],
                parameters)
        else:
            utils.write_interface_config_ethernet(
                management_interface,
                mgmt_network.logical_interface.mtu,
                parameters)

        # Restart networking with the new management interface configuration
        utils.restart_networking()

        # Send a GARP for floating address. Doing this to help in
        # cases where we are re-installing in a lab and another node
        # previously held the floating address.
        if mgmt_network.cidr.version == 4:
            utils.send_interface_garp(management_interface_name,
                                      mgmt_network.start_address)
    except Exception:
        LOG.exception("Failed to configure management interface")
        raise ConfigFail("Failed to configure management interface")


def create_cgcs_config_file(output_file, system_config,
                            services, endpoints, domains,
                            config_type=REGION_CONFIG, validate_only=False):
    """
    Create cgcs_config file or just perform validation of the system_config if
    validate_only=True.
    :param output_file: filename of output cgcs_config file
    :param system_config: system configuration
    :param services: keystone services (not used if validate_only)
    :param endpoints: keystone endpoints (not used if validate_only)
    :param domains: keystone domains (not used if validate_only)
    :param config_type: specify region, subcloud or standard config
    :param validate_only: used to validate the input system_config
    :return:
    """
    cgcs_config = None
    if not validate_only:
        cgcs_config = configparser.RawConfigParser()
        cgcs_config.optionxform = str

    # general error checking, if not validate_only cgcs config data is returned
    validate(system_config, config_type, cgcs_config)

    # Region configuration: services, endpoints and domain
    if config_type in [REGION_CONFIG, SUBCLOUD_CONFIG] and not validate_only:
        # The services and endpoints are not available in the validation phase
        region_1_name = system_config.get('SHARED_SERVICES', 'REGION_NAME')
        keystone_service_name = system_config.get('SHARED_SERVICES',
                                                  'KEYSTONE_SERVICE_NAME')
        keystone_service_type = system_config.get('SHARED_SERVICES',
                                                  'KEYSTONE_SERVICE_TYPE')
        keystone_service_id = services.get_service_id(keystone_service_name,
                                                      keystone_service_type)
        keystone_admin_url = endpoints.get_service_url(region_1_name,
                                                       keystone_service_id,
                                                       "admin")
        keystone_internal_url = endpoints.get_service_url(region_1_name,
                                                          keystone_service_id,
                                                          "internal")
        keystone_public_url = endpoints.get_service_url(region_1_name,
                                                        keystone_service_id,
                                                        "public")

        cgcs_config.set('cREGION', 'KEYSTONE_AUTH_URI', keystone_internal_url)
        cgcs_config.set('cREGION', 'KEYSTONE_IDENTITY_URI', keystone_admin_url)
        cgcs_config.set('cREGION', 'KEYSTONE_ADMIN_URI', keystone_admin_url)
        cgcs_config.set('cREGION', 'KEYSTONE_INTERNAL_URI',
                        keystone_internal_url)
        cgcs_config.set('cREGION', 'KEYSTONE_PUBLIC_URI', keystone_public_url)

        is_glance_cached = False
        if system_config.has_option('SHARED_SERVICES', 'GLANCE_CACHED'):
            if (system_config.get('SHARED_SERVICES',
                                  'GLANCE_CACHED').upper() == 'TRUE'):
                is_glance_cached = True
        cgcs_config.set('cREGION', 'GLANCE_CACHED', is_glance_cached)

        if (system_config.has_option('SHARED_SERVICES',
                                     'GLANCE_SERVICE_NAME') and
                not is_glance_cached):
            glance_service_name = system_config.get('SHARED_SERVICES',
                                                    'GLANCE_SERVICE_NAME')
            glance_service_type = system_config.get('SHARED_SERVICES',
                                                    'GLANCE_SERVICE_TYPE')
            glance_region_name = region_1_name
            glance_service_id = services.get_service_id(glance_service_name,
                                                        glance_service_type)
            glance_internal_url = endpoints.get_service_url(glance_region_name,
                                                            glance_service_id,
                                                            "internal")
            glance_public_url = endpoints.get_service_url(glance_region_name,
                                                          glance_service_id,
                                                          "public")

            cgcs_config.set('cREGION', 'GLANCE_ADMIN_URI', glance_internal_url)
            cgcs_config.set('cREGION', 'GLANCE_PUBLIC_URI', glance_public_url)
            cgcs_config.set('cREGION', 'GLANCE_INTERNAL_URI',
                            glance_internal_url)

        # if ldap is a shared service
        if (system_config.has_option('SHARED_SERVICES', 'LDAP_SERVICE_URL')):
            ldap_service_url = system_config.get('SHARED_SERVICES',
                                                 'LDAP_SERVICE_URL')
            cgcs_config.set('cREGION', 'LDAP_SERVICE_URI', ldap_service_url)
            cgcs_config.set('cREGION', 'LDAP_SERVICE_NAME', 'open-ldap')
            cgcs_config.set('cREGION', 'LDAP_REGION_NAME', region_1_name)

        # The domains are not available in the validation phase
        heat_admin_domain = system_config.get('REGION_2_SERVICES',
                                              'HEAT_ADMIN_DOMAIN')
        cgcs_config.set('cREGION', 'HEAT_ADMIN_DOMAIN_NAME', heat_admin_domain)

        # If primary region is non-TiC and keystone entries already created,
        # the flag will tell puppet not to create them.
        if (system_config.has_option('REGION_2_SERVICES', 'CREATE') and
                system_config.get('REGION_2_SERVICES', 'CREATE') == 'Y'):
            cgcs_config.set('cREGION', 'REGION_SERVICES_CREATE', 'True')

    # System Timezone configuration
    if system_config.has_option('SYSTEM', 'TIMEZONE'):
        timezone = system_config.get('SYSTEM', 'TIMEZONE')
        if not os.path.isfile("/usr/share/zoneinfo/%s" % timezone):
            raise ConfigFail(
                "Timezone file %s does not exist" % timezone)

    # Dump results for debugging
    # for section in cgcs_config.sections():
    #    print "[%s]" % section
    #    for (name, value) in cgcs_config.items(section):
    #        print "%s=%s" % (name, value)

    if not validate_only:
        # Write config file
        with open(output_file, 'w') as config_file:
            cgcs_config.write(config_file)


def configure_system(config_file):
    """Configure the system"""

    # Parse the system config file
    print("Parsing system configuration file... ", end=' ')
    system_config = parse_system_config(config_file)
    print("DONE")

    # Validate the system config file
    print("Validating system configuration file... ", end=' ')
    try:
        create_cgcs_config_file(None, system_config, None, None, None,
                                DEFAULT_CONFIG, validate_only=True)
    except configparser.Error as e:
        raise ConfigFail("Error parsing configuration file %s: %s" %
                         (config_file, e))
    print("DONE")

    # Create cgcs_config file
    print("Creating config apply file... ", end=' ')
    try:
        create_cgcs_config_file(TEMP_CGCS_CONFIG_FILE, system_config,
                                None, None, None, DEFAULT_CONFIG)
    except configparser.Error as e:
        raise ConfigFail("Error parsing configuration file %s: %s" %
                         (config_file, e))
    print("DONE")


def show_help():
    print("Usage: %s\n"
          "Perform system configuration\n"
          "\nThe default action is to perform the initial configuration for "
          "the system.\nThe following options are also available:\n"
          "--config-file <name>     Perform configuration using INI file\n"
          "--backup <name>          Backup configuration using the given "
          "name\n"
          "--clone-iso <name>       Clone and create an image with "
          "the given file name\n"
          "--clone-status           Status of the last installation of "
          "cloned image\n"
          "--restore-system "
          "<include-storage-reinstall | exclude-storage-reinstall> "
          "<name>\n"
          "                         Restore system configuration from backup "
          "file with\n"
          "                         the given name, full path required\n"
          "--restore-images <name>  Restore images from backup file with the "
          "given name,\n"
          "                         full path required\n"
          "--restore-complete       Complete restore of controller-0\n"
          "--allow-ssh              Allow configuration to be executed in "
          "ssh\n"
          % sys.argv[0])


def show_help_lab_only():
    print("Usage: %s\n"
          "Perform initial configuration\n"
          "\nThe following options are for lab use only:\n"
          "--answerfile <file>  Apply the configuration from the specified "
          "file without\n"
          "                     any validation or user interaction\n"
          "--default            Apply default configuration with no NTP or "
          "DNS server\n"
          "                     configuration (suitable for testing in a "
          "virtual\n"
          "                     environment)\n"
          "--archive-dir <dir>  Directory to store the archive in\n"
          "--provision          Provision initial system data only\n"
          % sys.argv[0])


def no_complete(text, state):
    return


def main():
    options = {}
    answerfile = None
    backup_name = None
    archive_dir = constants.BACKUPS_PATH
    do_default_config = False
    do_backup = False
    do_system_restore = False
    include_storage_reinstall = False
    do_images_restore = False
    do_complete_restore = False
    do_clone = False
    do_non_interactive = False
    do_provision = False
    system_config_file = "/home/wrsroot/system_config"
    allow_ssh = False

    # Disable completion as the default completer shows python commands
    readline.set_completer(no_complete)

    # remove any previous config fail flag file
    if os.path.exists(constants.CONFIG_FAIL_FILE) is True:
        os.remove(constants.CONFIG_FAIL_FILE)

    if os.environ.get('CGCS_LABMODE'):
        options['labmode'] = True

    arg = 1
    while arg < len(sys.argv):
        if sys.argv[arg] == "--answerfile":
            arg += 1
            if arg < len(sys.argv):
                answerfile = sys.argv[arg]
            else:
                print("--answerfile option requires a file to be specified")
                exit(1)
        elif sys.argv[arg] == "--backup":
            arg += 1
            if arg < len(sys.argv):
                backup_name = sys.argv[arg]
            else:
                print("--backup requires the name of the backup")
                exit(1)
            do_backup = True
        elif sys.argv[arg] == "--restore-system":
            arg += 1
            if arg < len(sys.argv):
                if sys.argv[arg] in ["include-storage-reinstall",
                                     "exclude-storage-reinstall"]:
                    if sys.argv[arg] == "include-storage-reinstall":
                        include_storage_reinstall = True
                    arg += 1
                    if arg < len(sys.argv):
                        backup_name = sys.argv[arg]
                    else:
                        print(textwrap.fill(
                            "--restore-system requires the filename "
                            " of the backup", 80))
                        exit(1)
                else:
                    backup_name = sys.argv[arg]
            else:
                print(textwrap.fill(
                    "--restore-system requires the filename "
                    "of the backup", 80))
                exit(1)
            do_system_restore = True
        elif sys.argv[arg] == "--restore-images":
            arg += 1
            if arg < len(sys.argv):
                backup_name = sys.argv[arg]
            else:
                print("--restore-images requires the filename of the backup")
                exit(1)
            do_images_restore = True
        elif sys.argv[arg] == "--restore-complete":
            do_complete_restore = True
        elif sys.argv[arg] == "--archive-dir":
            arg += 1
            if arg < len(sys.argv):
                archive_dir = sys.argv[arg]
            else:
                print("--archive-dir requires a directory")
                exit(1)
        elif sys.argv[arg] == "--clone-iso":
            arg += 1
            if arg < len(sys.argv):
                backup_name = sys.argv[arg]
            else:
                print("--clone-iso requires the name of the image")
                exit(1)
            do_clone = True
        elif sys.argv[arg] == "--clone-status":
            clone.clone_status()
            exit(0)
        elif sys.argv[arg] == "--default":
            do_default_config = True
        elif sys.argv[arg] == "--config-file":
            arg += 1
            if arg < len(sys.argv):
                system_config_file = sys.argv[arg]
            else:
                print("--config-file requires the filename of the config file")
                exit(1)
            do_non_interactive = True
        elif sys.argv[arg] in ["--help", "-h", "-?"]:
            show_help()
            exit(1)
        elif sys.argv[arg] == "--labhelp":
            show_help_lab_only()
            exit(1)
        elif sys.argv[arg] == "--provision":
            do_provision = True
        elif sys.argv[arg] == "--allow-ssh":
            allow_ssh = True
        elif sys.argv[arg] == "--kubernetes":
            # This is a temporary flag for use during development. Once things
            # are stable, we will remove it and make kubernetes the default.
            options['kubernetes'] = True
        else:
            print("Invalid option. Use --help for more information.")
            exit(1)
        arg += 1

    if [do_backup,
            do_system_restore,
            do_images_restore,
            do_complete_restore,
            do_clone,
            do_default_config,
            do_non_interactive].count(True) > 1:
        print("Invalid combination of options selected")
        exit(1)

    if answerfile and [do_backup,
                       do_system_restore,
                       do_images_restore,
                       do_complete_restore,
                       do_clone,
                       do_default_config,
                       do_non_interactive].count(True) > 0:
        print("The --answerfile option cannot be used with the selected "
              "option")
        exit(1)

    log.configure()

    if not do_backup and not do_clone:
        # Check if that the command is being run from the console
        if utils.is_ssh_parent():
            if allow_ssh:
                print(textwrap.fill(constants.SSH_WARNING_MESSAGE, 80))
                print('')
            else:
                print(textwrap.fill(constants.SSH_ERROR_MESSAGE, 80))
                exit(1)

    # Reduce the printk console log level to avoid noise during configuration
    printk_levels = ''
    with open('/proc/sys/kernel/printk', 'r') as f:
        printk_levels = f.readline()

    temp_printk_levels = '3' + printk_levels[1:]
    with open('/proc/sys/kernel/printk', 'w') as f:
        f.write(temp_printk_levels)

    try:
        if do_backup:
            backup_restore.backup(backup_name, archive_dir)
            print("\nBackup complete")
        elif do_system_restore:
            backup_restore.restore_system(backup_name,
                                          include_storage_reinstall)
            print("\nSystem restore complete")
        elif do_images_restore:
            backup_restore.restore_images(backup_name)
            print("\nImages restore complete")
        elif do_complete_restore:
            backup_restore.restore_complete()
        elif do_clone:
            clone.clone(backup_name, archive_dir)
            print("\nCloning complete")
        elif do_provision:
            assistant = ConfigAssistant(**options)
            assistant.provision(answerfile)
        else:
            if do_non_interactive:
                if not os.path.isfile(system_config_file):
                    raise ConfigFail("Config file %s does not exist." %
                                     system_config_file)
                if (os.path.exists(constants.CGCS_CONFIG_FILE) or
                        os.path.exists(constants.CONFIG_PERMDIR) or
                        os.path.exists(
                            constants.INITIAL_CONFIG_COMPLETE_FILE)):
                    raise ConfigFail("Configuration has already been done "
                                     "and cannot be repeated.")
                configure_system(system_config_file)
                answerfile = TEMP_CGCS_CONFIG_FILE
            assistant = ConfigAssistant(**options)
            assistant.configure(answerfile, do_default_config)
            print("\nConfiguration was applied\n")
            print(textwrap.fill(
                "Please complete any out of service commissioning steps "
                "with system commands and unlock controller to proceed.", 80))
            assistant.check_required_interfaces_status()

    except KeyboardInterrupt:
        print("\nAborting configuration")
    except BackupFail as e:
        print("\nBackup failed: {}".format(e))
    except RestoreFail as e:
        print("\nRestore failed: {}".format(e))
    except ConfigFail as e:
        print("\nConfiguration failed: {}".format(e))
    except CloneFail as e:
        print("\nCloning failed: {}".format(e))
    except UserQuit:
        print("\nAborted configuration")
    finally:
        if os.path.isfile(TEMP_CGCS_CONFIG_FILE):
            os.remove(TEMP_CGCS_CONFIG_FILE)

    # Restore the printk console log level
    with open('/proc/sys/kernel/printk', 'w') as f:
        f.write(printk_levels)
