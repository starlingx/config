"""
Copyright (c) 2014-2018 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

from six.moves import configparser
import datetime
import errno
import getpass
import hashlib
import keyring
import netifaces
import os
import re
import stat
import subprocess
import textwrap
import time

import pyudev
from configutilities import ConfigFail
from configutilities import ValidateFail
from configutilities import is_valid_vlan
from configutilities import is_mtu_valid
from configutilities import validate_network_str
from configutilities import validate_address_str
from configutilities import validate_address
from configutilities import ip_version_to_string
from configutilities import validate_nameserver_address_str
from configutilities import is_valid_url
from configutilities import is_valid_domain_or_ip
from configutilities import validate_openstack_password
from configutilities import DEFAULT_DOMAIN_NAME
from netaddr import IPNetwork
from netaddr import IPAddress
from netaddr import IPRange
from netaddr import AddrFormatError
from sysinv.common import constants as sysinv_constants
from tsconfig.tsconfig import SW_VERSION

from controllerconfig import openstack
from controllerconfig import sysinv_api as sysinv
from controllerconfig import utils
from controllerconfig import progress

from controllerconfig.common import constants
from controllerconfig.common import log
from controllerconfig.common.exceptions import KeystoneFail
from controllerconfig.common.exceptions import SysInvFail
from controllerconfig.common.exceptions import UserQuit
from six.moves import input

LOG = log.get_logger(__name__)

DEVNULL = open(os.devnull, 'w')


def interface_exists(name):
    """Check whether an interface exists."""
    return name in netifaces.interfaces()


def timestamped(dname, fmt='{dname}_%Y-%m-%d-%H-%M-%S'):
    return datetime.datetime.now().strftime(fmt).format(dname=dname)


def prompt_for(prompt_text, default_input, validator):
    """
    :param prompt_text: text for the prompt
    :param default_input: default input if user hit enter directly
    :param validator: validator function to validate user input,
                      validator should return error message in case
                      of invalid input, or None if input is valid.
    :return: return a valid user input
    """
    error_msg = None
    while True:
        user_input = input(prompt_text)
        if user_input.lower() == 'q':
            raise UserQuit
        elif user_input == "":
            user_input = default_input

        if validator:
            error_msg = validator(user_input)

        if error_msg is not None:
            print(error_msg)
        else:
            break

    return user_input


def is_interface_up(interface_name):
    arg = '/sys/class/net/' + interface_name + '/operstate'
    try:
        if (subprocess.check_output(['cat', arg]).rstrip() ==
                'up'):
            return True
        else:
            return False
    except subprocess.CalledProcessError:
        LOG.error("Command cat %s failed" % arg)
        return False


def device_node_to_device_path(dev_node):
    device_path = None
    cmd = ["find", "-L", "/dev/disk/by-path/", "-samefile", dev_node]

    try:
        out = subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        LOG.error("Could not retrieve device information: %s" % e)
        return device_path

    device_path = out.rstrip()
    return device_path


def parse_fdisk(device_node):
    """Cloned/modified from sysinv"""
    # Run command
    fdisk_command = ('fdisk -l %s 2>/dev/null | grep "Disk %s:"' %
                     (device_node, device_node))
    fdisk_process = subprocess.Popen(fdisk_command, stdout=subprocess.PIPE,
                                     shell=True)
    fdisk_output = fdisk_process.stdout.read()

    # Parse output
    secnd_half = fdisk_output.split(',')[1]
    size_bytes = secnd_half.split()[0].strip()

    # Convert bytes to GiB (1 GiB = 1024*1024*1024 bytes)
    int_size = int(size_bytes)
    size_gib = int_size / 1073741824

    return int(size_gib)


def get_rootfs_node():
    """Cloned from sysinv"""
    cmdline_file = '/proc/cmdline'
    device = None

    with open(cmdline_file, 'r') as f:
        for line in f:
            for param in line.split():
                params = param.split("=", 1)
                if params[0] == "root":
                    if "UUID=" in params[1]:
                        key, uuid = params[1].split("=")
                        symlink = "/dev/disk/by-uuid/%s" % uuid
                        device = os.path.basename(os.readlink(symlink))
                    else:
                        device = os.path.basename(params[1])

    if device is not None:
        if sysinv_constants.DEVICE_NAME_NVME in device:
            re_line = re.compile(r'^(nvme[0-9]*n[0-9]*)')
        else:
            re_line = re.compile(r'^(\D*)')
        match = re_line.search(device)
        if match:
            return os.path.join("/dev", match.group(1))

    return


def find_boot_device():
    """ Determine boot device """
    boot_device = None

    context = pyudev.Context()

    # Get the boot partition
    # Unfortunately, it seems we can only get it from the logfile.
    # We'll parse the device used from a line like the following:
    # BIOSBoot.create: device: /dev/sda1 ; status: False ; type: biosboot ;
    # or
    # EFIFS.create: device: /dev/sda1 ; status: False ; type: efi ;
    #
    logfile = '/var/log/anaconda/storage.log'

    re_line = re.compile(r'(BIOSBoot|EFIFS).create: device: ([^\s;]*)')
    boot_partition = None
    with open(logfile, 'r') as f:
        for line in f:
            match = re_line.search(line)
            if match:
                boot_partition = match.group(2)
                break
    if boot_partition is None:
        raise ConfigFail("Failed to determine the boot partition")

    # Find the boot partition and get its parent
    for device in context.list_devices(DEVTYPE='partition'):
        if device.device_node == boot_partition:
            boot_device = device.find_parent('block').device_node
            break

    if boot_device is None:
        raise ConfigFail("Failed to determine the boot device")

    return boot_device


def get_device_from_function(get_disk_function):
    device_node = get_disk_function()
    device_path = device_node_to_device_path(device_node)
    device = device_path if device_path else os.path.basename(device_node)

    return device


def get_console_info():
    """ Determine console info """
    cmdline_file = '/proc/cmdline'

    re_line = re.compile(r'^.*\s+console=([^\s]*)')

    with open(cmdline_file, 'r') as f:
        for line in f:
            match = re_line.search(line)
            if match:
                console_info = match.group(1)
                return console_info
    return ''


def get_orig_install_mode():
    """ Determine original install mode, text vs graphical """
    # Post-install, the only way to detemine the original install mode
    # will be to check the anaconda install log for the parameters passed
    logfile = '/var/log/anaconda/anaconda.log'

    search_str = 'Display mode = t'
    try:
        subprocess.check_call(['grep', '-q', search_str, logfile])
        return 'text'
    except subprocess.CalledProcessError:
        return 'graphical'


def get_root_disk_size():
    """ Get size of the root disk """
    context = pyudev.Context()
    rootfs_node = get_rootfs_node()
    size_gib = 0

    for device in context.list_devices(DEVTYPE='disk'):
        # /dev/nvmeXn1 259 are for NVME devices
        major = device['MAJOR']
        if (major == '8' or major == '3' or major == '253' or
                major == '259'):
            devname = device['DEVNAME']
            if devname == rootfs_node:
                try:
                    size_gib = parse_fdisk(devname)
                except Exception as e:
                    LOG.error("Could not retrieve disk size - %s " % e)
                    # Do not break config script, just return size 0
                    break
                break
    return size_gib


def net_device_cmp(a, b):
    # Sorting function for net devices
    # Break device name "devX" into "dev" and "X", in order
    # to numerically sort devices with same "dev" prefix.
    # For example, this ensures a device named enp0s10 comes
    # after enp0s3.

    pattern = re.compile("^(.*?)([0-9]*)$")
    a_match = pattern.match(a)
    b_match = pattern.match(b)

    if a_match.group(1) == b_match.group(1):
        a_num = int(a_match.group(2)) if a_match.group(2).isdigit() else 0
        b_num = int(b_match.group(2)) if b_match.group(2).isdigit() else 0
        return a_num - b_num
    elif a_match.group(1) < b_match.group(1):
        return -1
    return 1


def get_net_device_list():
    devlist = []
    context = pyudev.Context()
    for device in context.list_devices(SUBSYSTEM='net'):
        # Skip the loopback device
        if device.sys_name != "lo":
            devlist.append(str(device.sys_name))

    return sorted(devlist, cmp=net_device_cmp)


def get_tboot_info():
    """ Determine whether we were booted with a tboot value """
    cmdline_file = '/proc/cmdline'

    # tboot=true, tboot=false, or no tboot parameter expected
    re_line = re.compile(r'^.*\s+tboot=([^\s]*)')

    with open(cmdline_file, 'r') as f:
        for line in f:
            match = re_line.search(line)
            if match:
                tboot = match.group(1)
                return tboot
    return ''


class ConfigAssistant():
    """Allow user to do the initial configuration."""

    def __init__(self, labmode=False, kubernetes=False, **kwargs):
        """Constructor

        The values assigned here are used as the defaults if the user does not
        supply a new value.
        """

        self.labmode = labmode
        self.kubernetes = True

        self.config_uuid = "install"

        self.net_devices = get_net_device_list()
        if len(self.net_devices) < 2:
            raise ConfigFail("Two or more network devices are required")

        if os.path.exists(constants.INSTALLATION_FAILED_FILE):
            msg = "Installation failed. For more info, see:\n"
            with open(constants.INSTALLATION_FAILED_FILE, 'r') as f:
                msg += f.read()
            raise ConfigFail(msg)

        # system config
        self.system_type = utils.get_system_type()
        self.security_profile = utils.get_security_profile()

        if self.system_type == sysinv_constants.TIS_AIO_BUILD:
            self.system_mode = sysinv_constants.SYSTEM_MODE_DUPLEX_DIRECT
        else:
            self.system_mode = sysinv_constants.SYSTEM_MODE_DUPLEX
        self.system_dc_role = None

        self.rootfs_node = get_rootfs_node()

        # PXEBoot network config
        self.separate_pxeboot_network = False
        self.pxeboot_subnet = IPNetwork("192.168.202.0/24")
        self.controller_pxeboot_floating_address = IPNetwork("192.168.202.2")
        self.controller_pxeboot_address_0 = IPAddress("192.168.202.3")
        self.controller_pxeboot_address_1 = IPAddress("192.168.202.4")
        self.controller_pxeboot_hostname_suffix = "-pxeboot"
        self.private_pxeboot_subnet = IPNetwork("169.254.202.0/24")
        self.pxecontroller_floating_hostname = "pxecontroller"
        self.pxeboot_start_address = None
        self.pxeboot_end_address = None
        self.use_entire_pxeboot_subnet = True

        # Management network config
        self.management_interface_configured = False
        self.management_interface_name = self.net_devices[1]
        self.management_interface = self.net_devices[1]
        self.management_vlan = ""
        self.management_mtu = constants.LINK_MTU_DEFAULT
        self.next_lag_index = 0
        self.lag_management_interface = False
        self.lag_management_interface_member0 = self.net_devices[1]
        self.lag_management_interface_member1 = ""
        self.lag_management_interface_policy = constants.LAG_MODE_8023AD
        self.lag_management_interface_txhash = constants.LAG_TXHASH_LAYER2
        self.lag_management_interface_miimon = constants.LAG_MIIMON_FREQUENCY
        self.management_subnet = IPNetwork("192.168.204.0/24")
        self.management_gateway_address = None
        self.controller_floating_address = IPAddress("192.168.204.2")
        self.controller_address_0 = IPAddress("192.168.204.3")
        self.controller_address_1 = IPAddress("192.168.204.4")
        self.nfs_management_address_1 = IPAddress("192.168.204.5")
        self.nfs_management_address_2 = IPAddress("192.168.204.6")
        self.storage_address_0 = ""
        self.storage_address_1 = ""
        self.controller_floating_hostname = "controller"
        self.controller_hostname_prefix = "controller-"
        self.storage_hostname_prefix = "storage-"
        self.use_entire_mgmt_subnet = True
        self.dynamic_address_allocation = True
        self.management_start_address = IPAddress("192.168.204.2")
        self.management_end_address = IPAddress("192.168.204.254")
        self.management_multicast_subnet = \
            IPNetwork(constants.DEFAULT_MULTICAST_SUBNET_IPV4)

        # Infrastructure network config
        self.infrastructure_interface_configured = False
        self.infrastructure_interface_name = ""
        self.infrastructure_interface = ""
        self.infrastructure_vlan = ""
        self.infrastructure_mtu = constants.LINK_MTU_DEFAULT
        self.lag_infrastructure_interface = False
        self.lag_infrastructure_interface_member0 = ""
        self.lag_infrastructure_interface_member1 = ""
        self.lag_infrastructure_interface_policy = \
            constants.LAG_MODE_ACTIVE_BACKUP
        self.lag_infrastructure_interface_txhash = ""
        self.lag_infrastructure_interface_miimon = \
            constants.LAG_MIIMON_FREQUENCY
        self.infrastructure_subnet = IPNetwork("192.168.205.0/24")
        self.controller_infrastructure_address_0 = IPAddress("192.168.205.3")
        self.controller_infrastructure_address_1 = IPAddress("192.168.205.4")
        self.nfs_infrastructure_address_1 = IPAddress("192.168.205.5")
        self.storage_infrastructure_address_0 = ""
        self.storage_infrastructure_address_1 = ""
        self.controller_infrastructure_hostname_suffix = "-infra"
        self.use_entire_infra_subnet = True
        self.infrastructure_start_address = IPAddress("192.168.205.2")
        self.infrastructure_end_address = IPAddress("192.168.205.254")

        # External OAM Network config
        self.external_oam_interface_configured = False
        self.external_oam_interface_name = self.net_devices[0]
        self.external_oam_interface = self.net_devices[0]
        self.external_oam_vlan = ""
        self.external_oam_mtu = constants.LINK_MTU_DEFAULT
        self.lag_external_oam_interface = False
        self.lag_external_oam_interface_member0 = self.net_devices[0]
        self.lag_external_oam_interface_member1 = ""
        self.lag_external_oam_interface_policy = \
            constants.LAG_MODE_ACTIVE_BACKUP
        self.lag_external_oam_interface_txhash = ""
        self.lag_external_oam_interface_miimon = \
            constants.LAG_MIIMON_FREQUENCY
        self.external_oam_subnet = IPNetwork("10.10.10.0/24")
        self.external_oam_gateway_address = IPAddress("10.10.10.1")
        self.external_oam_floating_address = IPAddress("10.10.10.2")
        self.external_oam_address_0 = IPAddress("10.10.10.3")
        self.external_oam_address_1 = IPAddress("10.10.10.4")
        self.oamcontroller_floating_hostname = "oamcontroller"

        # Kubernetes cluster network config
        self.cluster_host_interface_configured = False
        self.cluster_host_interface_name = self.management_interface_name
        self.cluster_host_interface = self.management_interface
        self.cluster_host_vlan = ""
        self.cluster_host_mtu = constants.LINK_MTU_DEFAULT
        self.lag_cluster_host_interface = False
        self.lag_cluster_host_interface_member0 = ""
        self.lag_cluster_host_interface_member1 = ""
        self.lag_cluster_host_interface_policy = \
            constants.LAG_MODE_ACTIVE_BACKUP
        self.lag_cluster_host_interface_txhash = ""
        self.lag_cluster_host_interface_miimon = \
            constants.LAG_MIIMON_FREQUENCY
        self.cluster_host_subnet = IPNetwork("192.168.206.0/24")

        # Will be configurable in the future
        self.cluster_pod_subnet = IPNetwork("172.16.0.0/16")
        self.cluster_service_subnet = IPNetwork("10.96.0.0/12")

        # Docker Proxy config
        self.enable_docker_proxy = False
        self.docker_http_proxy = ""
        self.docker_https_proxy = ""
        self.docker_no_proxy = ""

        # Docker registry config
        self.docker_use_default_registry = True
        self.docker_k8s_registry = ""
        self.docker_gcr_registry = ""
        self.docker_quay_registry = ""
        self.docker_docker_registry = ""
        self.is_secure_registry = True

        # SDN config
        self.enable_sdn = False

        # DNS config
        self.nameserver_addresses = ["8.8.8.8", "8.8.4.4", ""]

        # HTTPS
        self.enable_https = False
        # Network config
        self.vswitch_type = "none"

        # Authentication config
        self.admin_username = "admin"
        self.admin_password = ""
        self.os_password_rules_file = constants.OPENSTACK_PASSWORD_RULES_FILE
        self.openstack_passwords = []

        # Region config
        self.region_config = False
        self.region_services_create = False
        self.shared_services = []
        self.external_oam_start_address = ""
        self.external_oam_end_address = ""
        self.region_1_name = ""
        self.region_2_name = ""
        self.admin_user_domain = DEFAULT_DOMAIN_NAME
        self.admin_project_name = ""
        self.admin_project_domain = DEFAULT_DOMAIN_NAME
        self.service_project_name = constants.DEFAULT_SERVICE_PROJECT_NAME
        self.service_user_domain = DEFAULT_DOMAIN_NAME
        self.service_project_domain = DEFAULT_DOMAIN_NAME
        self.keystone_auth_uri = ""
        self.keystone_identity_uri = ""
        self.keystone_admin_uri = ""
        self.keystone_internal_uri = ""
        self.keystone_public_uri = ""
        self.keystone_service_name = ""
        self.keystone_service_type = ""
        self.patching_ks_user_name = ""
        self.patching_ks_password = ""
        self.sysinv_ks_user_name = ""
        self.sysinv_ks_password = ""
        self.sysinv_service_name = ""
        self.sysinv_service_type = ""
        self.mtce_ks_user_name = ""
        self.mtce_ks_password = ""
        self.nfv_ks_user_name = ""
        self.nfv_ks_password = ""
        self.fm_ks_user_name = ""
        self.fm_ks_password = ""
        self.barbican_ks_user_name = ""
        self.barbican_ks_password = ""

        self.ldap_region_name = ""
        self.ldap_service_name = ""
        self.ldap_service_uri = ""

        # Subcloud config (only valid when region configured)
        self.system_controller_subnet = None

        # LDAP config
        self.ldapadmin_password = ""
        self.ldapadmin_hashed_pw = ""

        # Time Zone config
        self.timezone = "UTC"

        # saved service passwords, indexed by service name
        self._service_passwords = {}

    @staticmethod
    def set_time():
        """Allow user to set the system date and time."""

        print("System date and time:")
        print("---------------------\n")
        print(textwrap.fill(
              "The system date and time must be set now. Note that UTC "
              "time must be used and that the date and time must be set as "
              "accurately as possible, even if NTP/PTP is to be configured "
              "later.", 80))
        print('')

        now = datetime.datetime.utcnow()
        date_format = '%Y-%m-%d %H:%M:%S'
        print("Current system date and time (UTC): " +
              now.strftime(date_format))

        while True:
            user_input = input(
                "\nIs the current date and time correct? [y/n]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input.lower() == 'y':
                print("Current system date and time will be used.")
                return
            elif user_input.lower() == 'n':
                break
            else:
                print("Invalid choice")

        new_time = None
        while True:
            user_input = input("\nEnter new system date and time (UTC) " +
                               "in YYYY-MM-DD HH:MM:SS format: \n")
            if user_input.lower() == 'q':
                raise UserQuit
            else:
                try:
                    new_time = datetime.datetime.strptime(user_input,
                                                          date_format)
                    break
                except ValueError:
                    print("Invalid date and time specified")
                    continue

        # Set the system clock
        try:
            subprocess.check_call(["date", "-s", new_time.isoformat()])

        except subprocess.CalledProcessError:
            LOG.error("Failed to set system date and time")
            raise ConfigFail("Failed to set system date and time")

        # Set the hardware clock in UTC time
        try:
            subprocess.check_call(["hwclock", "-wu"])
        except subprocess.CalledProcessError:
            LOG.error("Failed to set the hardware clock")
            raise ConfigFail("Failed to set the hardware clock")

    @staticmethod
    def set_timezone(self):
        """Allow user to set the system timezone."""

        print("\nSystem timezone:")
        print("----------------\n")
        print(textwrap.fill(
              "The system timezone must be set now. The timezone "
              "must be a valid timezone from /usr/share/zoneinfo "
              "(e.g. UTC, Asia/Hong_Kong, etc...)", 80))
        print('')

        while True:
            user_input = input(
                "Please input the timezone[" + self.timezone + "]:")

            if user_input == 'Q' or user_input == 'q':
                raise UserQuit
            elif user_input == "":
                    break
            else:
                if not os.path.isfile("/usr/share/zoneinfo/%s" % user_input):
                    print("Invalid timezone specified, please try again.")
                    continue
                self.timezone = user_input
                break
        return

    def subcloud_config(self):
        return (self.system_dc_role ==
                sysinv_constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD)

    def get_next_lag_name(self):
        """Return next available name for LAG interface."""
        name = 'bond' + str(self.next_lag_index)
        self.next_lag_index += 1
        return name

    def get_wrsroot_sig(self):
        """ Get signature for wrsroot user. """

        # NOTE (knasim): only compute the signature for the entries we're
        # tracking and propagating {password, aging}. This is prevent
        # config-outdated alarms for shadow fields that get modified
        # and we don't track and propagate
        re_line = re.compile(r'(wrsroot:.*?)\s')
        with open('/etc/shadow') as shadow_file:
            for line in shadow_file:
                match = re_line.search(line)
                if match:
                    # Isolate password(2nd field) and aging(5th field)
                    entry = match.group(1).split(':')
                    entrystr = entry[1] + ":" + entry[4]
                    self.wrsroot_sig = hashlib.md5(entrystr).hexdigest()
                    self.passwd_hash = entry[1]

    def input_system_mode_config(self):
        """Allow user to input system mode"""
        print("\nSystem Configuration:")
        print("---------------------\n")
        print("System mode. Available options are:\n")
        print(textwrap.fill(
              "1) duplex-direct - two node redundant configuration. "
              "Management and infrastructure networks "
              "are directly connected to peer ports", 80))
        print(textwrap.fill(
              "2) duplex - two node redundant configuration. ", 80))

        print(textwrap.fill(
              "3) simplex - single node non-redundant configuration.", 80))

        value_mapping = {
            "1": sysinv_constants.SYSTEM_MODE_DUPLEX_DIRECT,
            "2": sysinv_constants.SYSTEM_MODE_DUPLEX,
            '3': sysinv_constants.SYSTEM_MODE_SIMPLEX
        }
        user_input = prompt_for(
            "System mode [duplex-direct]: ", '1',
            lambda text: "Invalid choice" if text not in value_mapping
            else None
        )
        self.system_mode = value_mapping[user_input.lower()]

    def input_dc_selection(self):
        """Allow user to input dc role"""
        print("\nDistributed Cloud Configuration:")
        print("--------------------------------\n")

        value_mapping = {
            "y": sysinv_constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER,
            "n": None,
        }
        user_input = prompt_for(
            "Configure Distributed Cloud System Controller [y/N]: ", 'n',
            lambda text: "Invalid choice" if text.lower() not in value_mapping
            else None
        )
        self.system_dc_role = value_mapping[user_input.lower()]

    def check_storage_config(self):
        """Check basic storage config."""

        if get_root_disk_size() < constants.MINIMUM_ROOT_DISK_SIZE:
            print(textwrap.fill(
                  "Warning: Root Disk %s size is less than %d GiB.  "
                  "Please consult the Software Installation Guide "
                  "for details." %
                  (self.rootfs_node, constants.MINIMUM_ROOT_DISK_SIZE), 80))
            print('')

    def is_interface_in_bond(self, interface_name):
        """
        Determine if the supplied interface is configured as a member
        in a bond.

        :param interface_name: interface to check
        :return: True or False
        """
        # In the case of bond with a single member
        if interface_name == "":
            return False

        if ((self.management_interface_configured and
             self.lag_management_interface and
             (interface_name == self.lag_management_interface_member0 or
              interface_name == self.lag_management_interface_member1))
            or
            (self.infrastructure_interface_configured and
             self.lag_infrastructure_interface and
             (interface_name == self.lag_infrastructure_interface_member0 or
              interface_name == self.lag_infrastructure_interface_member1))
            or
            (self.external_oam_interface_configured and
             self.lag_external_oam_interface and
             (interface_name == self.lag_external_oam_interface_member0 or
              interface_name == self.lag_external_oam_interface_member1))
            or
            (self.cluster_host_interface_configured and
             self.lag_cluster_host_interface and
             (interface_name == self.lag_cluster_host_interface_member0 or
              interface_name == self.lag_cluster_host_interface_member1))):
            return True
        else:
            return False

    def is_interface_in_use(self, interface_name):
        """
        Determine if the supplied interface is already configured for use

        :param interface_name: interface to check
        :return: True or False
        """
        if ((self.management_interface_configured and
             interface_name == self.management_interface) or
            (self.infrastructure_interface_configured and
             interface_name == self.infrastructure_interface) or
            (self.external_oam_interface_configured and
             interface_name == self.external_oam_interface) or
            (self.cluster_host_interface_configured and
             interface_name == self.cluster_host_interface)):
            return True
        else:
            return False

    def is_valid_pxeboot_address(self, ip_address):
        """Determine whether a pxeboot address is valid."""
        if ip_address.version != 4:
            print("Invalid IP version - only IPv4 supported")
            return False
        elif ip_address == self.pxeboot_subnet.network:
            print("Cannot use network address")
            return False
        elif ip_address == self.pxeboot_subnet.broadcast:
            print("Cannot use broadcast address")
            return False
        elif ip_address.is_multicast():
            print("Invalid network address - multicast address not allowed")
            return False
        elif ip_address.is_loopback():
            print("Invalid network address - loopback address not allowed")
            return False
        elif ip_address not in self.pxeboot_subnet:
            print("Address must be in the PXEBoot subnet")
            return False
        else:
            return True

    def default_pxeboot_config(self):
        """Set pxeboot to default private network."""

        # Use private subnet for pxe booting
        self.separate_pxeboot_network = False
        self.pxeboot_subnet = self.private_pxeboot_subnet
        self.controller_pxeboot_floating_address = \
            IPAddress(self.pxeboot_subnet[2])
        self.controller_pxeboot_address_0 = \
            IPAddress(self.pxeboot_subnet[3])
        self.controller_pxeboot_address_1 = \
            IPAddress(self.pxeboot_subnet[4])

        self.pxeboot_start_address = self.pxeboot_subnet[2]
        self.pxeboot_end_address = self.pxeboot_subnet[-2]

    def input_pxeboot_config(self):
        """Allow user to input pxeboot config and perform validation."""

        print("\nPXEBoot Network:")
        print("----------------\n")

        print(textwrap.fill(
            "The PXEBoot network is used for initial booting and installation"
            " of each node. IP addresses on this network are reachable only "
            "within the data center.", 80))
        print('')
        print(textwrap.fill(
              "The default configuration combines the PXEBoot network and the "
              "management network. If a separate PXEBoot network is used, it "
              "will share the management interface, which requires the "
              "management network to be placed on a VLAN.", 80))

        while True:
            print('')
            user_input = input(
                "Configure a separate PXEBoot network [y/N]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input.lower() == 'y':
                self.separate_pxeboot_network = True
                break
            elif user_input.lower() == 'n':
                self.separate_pxeboot_network = False
                break
            elif user_input == "":
                break
            else:
                print("Invalid choice")
                continue

        if self.separate_pxeboot_network:
            while True:
                user_input = input("PXEBoot subnet [" +
                                   str(self.pxeboot_subnet) + "]: ")
                if user_input.lower() == 'q':
                    raise UserQuit
                elif user_input == "":
                    user_input = self.pxeboot_subnet

                try:
                    ip_input = IPNetwork(user_input)
                    if ip_input.version != 4:
                        print("Invalid IP version - only IPv4 supported")
                        continue
                    elif ip_input.ip != ip_input.network:
                        print("Invalid network address")
                        continue
                    elif ip_input.size < 16:
                        print("PXEBoot subnet too small "
                              "- must have at least 16 addresses")
                        continue

                    if ip_input.size < 255:
                        print("WARNING: Subnet allows only %d addresses."
                              % ip_input.size)

                    self.pxeboot_subnet = ip_input
                    break
                except AddrFormatError:
                    print("Invalid subnet - please enter a valid IPv4 subnet")

            value_mapping = {
                "y": True,
                "n": False,
            }

            user_input = prompt_for(
                "Use entire PXEBoot subnet [Y/n]: ", 'Y',
                lambda text: "Invalid choice"
                             if text.lower() not in value_mapping
                             else None
            )
            self.use_entire_pxeboot_subnet = value_mapping[user_input.lower()]

            if not self.use_entire_pxeboot_subnet:
                def validate_input_address(text, error_header):
                    try:
                        validate_address_str(text, self.pxeboot_subnet)
                        return None
                    except ValidateFail as e:
                        return "%s\n Reason: %s" % (error_header, e)

                while True:
                    self.pxeboot_start_address = self.pxeboot_subnet[2]
                    self.pxeboot_end_address = self.pxeboot_subnet[-2]
                    input_str = prompt_for(
                        "PXEBoot network start address [" +
                        str(self.pxeboot_start_address) +
                        "]: ", str(self.pxeboot_start_address),
                        lambda text: validate_input_address(
                            text, "Invalid start address.")
                    )
                    self.pxeboot_start_address = IPAddress(input_str)

                    input_str = prompt_for(
                        "PXEBoot network end address [" +
                        str(self.pxeboot_end_address) +
                        "]: ", str(self.pxeboot_end_address),
                        lambda text: validate_input_address(
                            text, "Invalid end address.")
                    )
                    self.pxeboot_end_address = IPAddress(input_str)

                    if not self.pxeboot_start_address < \
                            self.pxeboot_end_address:
                        print("Start address not less than end address. ")
                        continue

                    address_range = IPRange(
                        str(self.pxeboot_start_address),
                        str(self.pxeboot_end_address))

                    min_addresses = 8
                    if not address_range.size >= min_addresses:
                        print(
                            "Address range must contain at least "
                            "%d addresses." % min_addresses)
                        continue

                    print('')
                    break
            else:
                self.pxeboot_start_address = self.pxeboot_subnet[2]
                self.pxeboot_end_address = self.pxeboot_subnet[-2]
        else:
            # Use private subnet for pxe booting
            self.pxeboot_subnet = self.private_pxeboot_subnet
            self.pxeboot_start_address = self.pxeboot_subnet[2]
            self.pxeboot_end_address = self.pxeboot_subnet[-2]

        ip_input = self.pxeboot_start_address
        if not self.is_valid_pxeboot_address(ip_input):
            raise ConfigFail("Unable to create controller PXEBoot "
                             "floating address")
        self.controller_pxeboot_floating_address = ip_input

        default_controller0_pxeboot_ip = \
            self.controller_pxeboot_floating_address + 1
        ip_input = IPAddress(default_controller0_pxeboot_ip)
        if not self.is_valid_pxeboot_address(ip_input):
            raise ConfigFail("Unable to create controller-0 PXEBoot "
                             "address")
        self.controller_pxeboot_address_0 = ip_input

        default_controller1_pxeboot_ip = self.controller_pxeboot_address_0 + 1
        ip_input = IPAddress(default_controller1_pxeboot_ip)
        if not self.is_valid_pxeboot_address(ip_input):
            raise ConfigFail("Unable to create controller-1 PXEBoot "
                             "address")
        self.controller_pxeboot_address_1 = ip_input

    def input_management_config(self):
        """Allow user to input management config and perform validation."""

        print("\nManagement Network:")
        print("-------------------\n")

        print(textwrap.fill(
            "The management network is used for internal communication "
            "between platform components. IP addresses on this network "
            "are reachable only within the data center.", 80))

        while True:
            print('')
            print(textwrap.fill(
                "A management bond interface provides redundant "
                "connections for the management network.", 80))
            if self.system_mode == sysinv_constants.SYSTEM_MODE_DUPLEX_DIRECT:
                print(textwrap.fill(
                    "It is strongly recommended to configure Management "
                    "interface link aggregation, for All-in-one duplex-direct."
                ))
            print('')
            user_input = input(
                "Management interface link aggregation [y/N]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input.lower() == 'y':
                self.lag_management_interface = True
                break
            elif user_input.lower() == 'n':
                self.lag_management_interface = False
                break
            elif user_input == "":
                break
            else:
                print("Invalid choice")
                continue

        while True:
            if self.lag_management_interface:
                self.management_interface = self.get_next_lag_name()

            user_input = input("Management interface [" +
                               str(self.management_interface) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == "":
                user_input = self.management_interface
            elif self.lag_management_interface:
                print(textwrap.fill(
                      "Warning: The default name for the management bond "
                      "interface (%s) cannot be changed." %
                      self.management_interface, 80))
                print('')
                user_input = self.management_interface

            if self.is_interface_in_bond(user_input):
                print(textwrap.fill(
                      "Interface is already configured as part of an "
                      "aggregated interface.", 80))
                continue
            elif self.lag_management_interface:
                self.management_interface = user_input
                self.management_interface_name = user_input
                break
            elif interface_exists(user_input):
                self.management_interface = user_input
                self.management_interface_name = user_input
                break
            else:
                print("Interface does not exist")
                continue

        while True:
            user_input = input("Management interface MTU [" +
                               str(self.management_mtu) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == "":
                user_input = self.management_mtu

            if is_mtu_valid(user_input):
                self.management_mtu = user_input
                break
            else:
                print("MTU is invalid/unsupported")
                continue

        while True:
            if not self.lag_management_interface:
                break

            print('')
            print("Specify one of the bonding policies. Possible values are:")
            print("  1) 802.3ad (LACP) policy")
            print("  2) Active-backup policy")

            user_input = input(
                "\nManagement interface bonding policy [" +
                str(self.lag_management_interface_policy) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == '1':
                self.lag_management_interface_policy = \
                    constants.LAG_MODE_8023AD
                break
            elif user_input == '2':
                self.lag_management_interface_policy = \
                    constants.LAG_MODE_ACTIVE_BACKUP
                self.lag_management_interface_txhash = None
                break
            elif user_input == "":
                break
            else:
                print("Invalid choice")
                continue

        while True:
            if not self.lag_management_interface:
                break

            print(textwrap.fill(
                  "A maximum of 2 physical interfaces can be attached to the "
                  "management interface.", 80))
            print('')

            user_input = input(
                "First management interface member [" +
                str(self.lag_management_interface_member0) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == "":
                user_input = self.lag_management_interface_member0

            if self.is_interface_in_bond(user_input):
                print(textwrap.fill(
                    "Interface is already configured as part of an "
                    "aggregated interface.", 80))
                continue
            elif self.is_interface_in_use(user_input):
                print("Interface is already in use")
                continue
            elif interface_exists(user_input):
                self.lag_management_interface_member0 = user_input
            else:
                print("Interface does not exist")
                self.lag_management_interface_member0 = ""
                continue

            user_input = input(
                "Second management interface member [" +
                str(self.lag_management_interface_member1) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == self.lag_management_interface_member0:
                print("Cannot use member 0 as member 1")
                continue
            elif user_input == "":
                user_input = self.lag_management_interface_member1

            if self.is_interface_in_bond(user_input):
                print(textwrap.fill(
                    "Interface is already configured as part of an "
                    "aggregated interface.", 80))
                continue
            elif self.is_interface_in_use(user_input):
                print("Interface is already in use")
                continue
            elif interface_exists(user_input):
                self.lag_management_interface_member1 = user_input
                break
            else:
                print("Interface does not exist")
                self.lag_management_interface_member1 = ""
                user_input = input(
                    "Do you want a single physical member in the bond "
                    "interface [y/n]: ")
                if user_input.lower() == 'q':
                    raise UserQuit
                elif user_input.lower() == 'y':
                    break
                elif user_input.lower() == 'n':
                    continue

        if self.separate_pxeboot_network:
            print('')
            print(textwrap.fill(
                "A management VLAN is required because a separate PXEBoot "
                "network was configured on the management interface.", 80))
            print('')

            while True:
                user_input = input(
                    "Management VLAN Identifier [" +
                    str(self.management_vlan) + "]: ")
                if user_input.lower() == 'q':
                    raise UserQuit
                elif is_valid_vlan(user_input):
                    self.management_vlan = user_input
                    self.management_interface_name = \
                        self.management_interface + '.' + self.management_vlan
                    break
                else:
                    print("VLAN is invalid/unsupported")
                    continue

        min_addresses = 8
        while True:
            user_input = input("Management subnet [" +
                               str(self.management_subnet) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == "":
                user_input = self.management_subnet

            try:
                tmp_management_subnet = validate_network_str(user_input,
                                                             min_addresses)
                if (tmp_management_subnet.version == 6 and
                   not self.separate_pxeboot_network):
                    print("Using IPv6 management network requires " +
                          "use of separate PXEBoot network")
                    continue
                self.management_subnet = tmp_management_subnet
                self.management_start_address = self.management_subnet[2]
                self.management_end_address = self.management_subnet[-2]
                if self.management_subnet.size < 255:
                    print("WARNING: Subnet allows only %d addresses.\n"
                          "This will not allow you to provision a Cinder LVM"
                          " or Ceph backend." % self.management_subnet.size)
                    while True:
                        user_input = raw_input(
                            "Do you want to continue with the current "
                            "configuration? [Y/n]: ")
                        if user_input.lower() == 'q' or \
                                user_input.lower() == 'n':
                            raise UserQuit
                        elif user_input.lower() == 'y' or user_input == "":
                            break
                        else:
                            print("Invalid choice")
                            continue
                break
            except ValidateFail as e:
                print("{}".format(e))

        if (self.system_dc_role !=
                sysinv_constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER):
            while True:
                user_input = input(
                    "Use entire management subnet [Y/n]: ")
                if user_input.lower() == 'q':
                    raise UserQuit
                elif user_input.lower() == 'y':
                    self.use_entire_mgmt_subnet = True
                    break
                elif user_input.lower() == 'n':
                    self.use_entire_mgmt_subnet = False
                    break
                elif user_input == "":
                    break
                else:
                    print("Invalid choice")
                    continue
        else:
            self.use_entire_mgmt_subnet = False
            print(textwrap.fill(
                "Configured as Distributed Cloud System Controller,"
                " disallowing use of entire management subnet.  "
                "Ensure management ip range does not include System"
                " Controller gateway address(es)", 80))

        if not self.use_entire_mgmt_subnet:
            while True:
                self.management_start_address = self.management_subnet[2]
                self.management_end_address = self.management_subnet[-2]
                while True:
                    user_input = input(
                        "Management network start address [" +
                        str(self.management_start_address) + "]: ")
                    if user_input.lower() == 'q':
                        raise UserQuit
                    elif user_input == "":
                        user_input = self.management_start_address

                    try:
                        self.management_start_address = validate_address_str(
                            user_input, self.management_subnet)
                        break
                    except ValidateFail as e:
                        print("Invalid start address. \n Reason: %s" % e)

                while True:
                    user_input = input(
                        "Management network end address [" +
                        str(self.management_end_address) + "]: ")
                    if user_input == 'Q' or user_input == 'q':
                        raise UserQuit
                    elif user_input == "":
                        user_input = self.management_end_address

                    try:
                        self.management_end_address = validate_address_str(
                            user_input, self.management_subnet)
                        break
                    except ValidateFail as e:
                        print("Invalid management end address. \n"
                              "Reason: %s" % e)

                if not self.management_start_address < \
                        self.management_end_address:
                    print("Start address not less than end address. ")
                    print('')
                    continue

                address_range = IPRange(str(self.management_start_address),
                                        str(self.management_end_address))
                if not address_range.size >= min_addresses:
                    print(
                        "Address range must contain at least %d addresses. " %
                        min_addresses)
                    continue

                sc = sysinv_constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER
                if (self.system_dc_role == sc):
                    # Warn user that some space in the management subnet must
                    # be reserved for the system controller gateway address(es)
                    # used to communicate with the subclouds. - 2 because of
                    # subnet and broadcast addresses.
                    if address_range.size >= (self.management_subnet.size - 2):
                        print(textwrap.fill(
                            "Address range too large, no addresses left "
                            "for System Controller gateway(s). ", 80))
                        continue
                break
        while True:
            print('')
            if self.kubernetes:
                print(textwrap.fill(
                    "IP addresses can be assigned to hosts dynamically or "
                    "a static IP address can be specified for each host. "
                    "This choice applies to both the management network "
                    "and cluster-host network. ", 80))
            else:
                print(textwrap.fill(
                    "IP addresses can be assigned to hosts dynamically or "
                    "a static IP address can be specified for each host. "
                    "This choice applies to both the management network "
                    "and infrastructure network (if configured). ", 80))
            print(textwrap.fill(
                "Warning: Selecting 'N', or static IP address allocation, "
                "disables automatic provisioning of new hosts in System "
                "Inventory, requiring the user to manually provision using "
                "the 'system host-add' command. ", 80))
            user_input = input(
                "Dynamic IP address allocation [Y/n]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input.lower() == 'y':
                self.dynamic_address_allocation = True
                break
            elif user_input.lower() == 'n':
                self.dynamic_address_allocation = False
                break
            elif user_input == "":
                break
            else:
                print("Invalid choice")
                continue

        default_controller0_mgmt_float_ip = self.management_start_address
        ip_input = IPAddress(default_controller0_mgmt_float_ip)
        try:
            validate_address(ip_input, self.management_subnet)
        except ValidateFail:
            raise ConfigFail("Unable to create controller-0 Management "
                             "floating address")
        self.controller_floating_address = ip_input

        default_controller0_mgmt_ip = self.controller_floating_address + 1
        ip_input = IPAddress(default_controller0_mgmt_ip)
        try:
            validate_address(ip_input, self.management_subnet)
        except ValidateFail:
            raise ConfigFail("Unable to create controller-0 Management "
                             "address")
        self.controller_address_0 = ip_input

        default_controller1_mgmt_ip = self.controller_address_0 + 1
        ip_input = IPAddress(default_controller1_mgmt_ip)
        try:
            validate_address(ip_input, self.management_subnet)
        except ValidateFail:
            raise ConfigFail("Unable to create controller-1 Management "
                             "address")
        self.controller_address_1 = ip_input

        first_nfs_ip = self.controller_address_1 + 1

        """ create default Management NFS addresses """
        default_nfs_ip = IPAddress(first_nfs_ip)
        try:
            validate_address(default_nfs_ip, self.management_subnet)
        except ValidateFail:
            raise ConfigFail("Unable to create NFS Management address 1")
        self.nfs_management_address_1 = default_nfs_ip

        default_nfs_ip = IPAddress(self.nfs_management_address_1 + 1)
        try:
            validate_address(default_nfs_ip, self.management_subnet)
        except ValidateFail:
            raise ConfigFail("Unable to create NFS Management address 2")
        self.nfs_management_address_2 = default_nfs_ip

        while True:
            if self.management_subnet.version == 6:
                # Management subnet is IPv6, so update the default value
                self.management_multicast_subnet = \
                    IPNetwork(constants.DEFAULT_MULTICAST_SUBNET_IPV6)

            user_input = input("Management Network Multicast subnet [" +
                               str(self.management_multicast_subnet) +
                               "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == "":
                user_input = self.management_multicast_subnet

            try:
                ip_input = IPNetwork(user_input)
                if not self.is_valid_management_multicast_subnet(ip_input):
                    continue
                self.management_multicast_subnet = ip_input
                break
            except AddrFormatError:
                print("Invalid subnet - "
                      "please enter a valid IPv4 or IPv6 subnet"
                      )

        """ Management interface configuration complete"""
        self.management_interface_configured = True

    def input_aio_simplex_management_config(self, management_subnet=None):
        """Allow user to input AIO simplex management config and perform
        validation."""

        if management_subnet is not None:
            self.management_subnet = management_subnet
        else:
            print("\nManagement Network:")
            print("-------------------\n")

            print(textwrap.fill(
                "The management network is used for internal communication "
                "between platform components. IP addresses on this network "
                "are reachable only within the host.", 80))
            print('')

            self.management_subnet = IPNetwork(
                constants.DEFAULT_MGMT_ON_LOOPBACK_SUBNET_IPV4)
            min_addresses = 16
            while True:
                user_input = input("Management subnet [" +
                                   str(self.management_subnet) + "]: ")
                if user_input.lower() == 'q':
                    raise UserQuit
                elif user_input == "":
                    user_input = self.management_subnet

                try:
                    tmp_management_subnet = validate_network_str(user_input,
                                                                 min_addresses)
                    if tmp_management_subnet.version == 6:
                        print("IPv6 management network not supported on " +
                              "simplex configuration")
                        continue
                    self.management_subnet = tmp_management_subnet
                    break
                except ValidateFail as e:
                    print("{}".format(e))

        self.management_interface = constants.LOOPBACK_IFNAME
        self.management_interface_name = constants.LOOPBACK_IFNAME
        self.management_start_address = self.management_subnet[2]
        self.management_end_address = self.management_subnet[-2]
        self.controller_floating_address = self.management_start_address
        self.controller_address_0 = self.management_start_address + 1
        self.controller_address_1 = self.management_start_address + 2

        """ create default Management NFS addresses """
        self.nfs_management_address_1 = self.controller_address_1 + 1
        self.nfs_management_address_2 = self.controller_address_1 + 2

        """ Management interface configuration complete"""
        self.management_interface_configured = True

    def is_valid_infrastructure_address(self, ip_address):
        """Determine whether an infrastructure address is valid."""
        if ip_address == self.infrastructure_subnet.network:
            print("Cannot use network address")
            return False
        elif ip_address == self.infrastructure_subnet.broadcast:
            print("Cannot use broadcast address")
            return False
        elif ip_address.is_multicast():
            print("Invalid network address - multicast address not allowed")
            return False
        elif ip_address.is_loopback():
            print("Invalid network address - loopback address not allowed")
            return False
        elif ip_address not in self.infrastructure_subnet:
            print("Address must be in the infrastructure subnet")
            return False
        else:
            return True

    def input_infrastructure_config(self):
        """Allow user to input infrastructure config and perform validation."""

        print("\nInfrastructure Network:")
        print("-----------------------\n")

        print(textwrap.fill(
            "The infrastructure network is used for internal communication "
            "between platform components to offload the management network "
            "of high bandwidth services. "
            "IP addresses on this network are reachable only within the data "
            "center.", 80))
        print('')
        print(textwrap.fill(
            "If a separate infrastructure interface is not configured the "
            "management network will be used.", 80))
        print('')

        if self.system_mode == sysinv_constants.SYSTEM_MODE_DUPLEX_DIRECT:
            print(textwrap.fill(
                "It is NOT recommended to configure infrastructure network "
                "for All-in-one duplex-direct."
            ))

        infra_vlan_required = False

        while True:
            user_input = input(
                "Configure an infrastructure interface [y/N]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input.lower() == 'y':
                break
            elif user_input.lower() in ('n', ''):
                self.infrastructure_interface = ""
                return
            else:
                print("Invalid choice")
                continue

        while True:
            print('')
            print(textwrap.fill(
                "An infrastructure bond interface provides redundant "
                "connections for the infrastructure network.", 80))
            print('')
            user_input = input(
                "Infrastructure interface link aggregation [y/N]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input.lower() == 'y':
                self.lag_infrastructure_interface = True
                break
            elif user_input.lower() in ('n', ''):
                self.lag_infrastructure_interface = False
                break
            else:
                print("Invalid choice")
                continue

        while True:
            if self.lag_infrastructure_interface:
                self.infrastructure_interface = self.get_next_lag_name()

            user_input = input("Infrastructure interface [" +
                               str(self.infrastructure_interface) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == '':
                user_input = self.infrastructure_interface
                if user_input == '':
                    print("Invalid interface")
                    continue
            elif self.lag_infrastructure_interface:
                print(textwrap.fill(
                    "Warning: The default name for the infrastructure bond "
                    "interface (%s) cannot be changed." %
                    self.infrastructure_interface, 80))
                print('')
                user_input = self.infrastructure_interface

            if self.is_interface_in_bond(user_input):
                print(textwrap.fill(
                    "Interface is already configured as part of an "
                    "aggregated interface.", 80))
                continue
            elif self.lag_infrastructure_interface:
                self.infrastructure_interface = user_input
                self.infrastructure_interface_name = user_input
                break
            elif (interface_exists(user_input) or
                  user_input == self.management_interface or
                  user_input == self.external_oam_interface):
                self.infrastructure_interface = user_input
                self.infrastructure_interface_name = user_input
                if (self.external_oam_interface_configured and
                    user_input == self.external_oam_interface and
                        not self.external_oam_vlan):
                    infra_vlan_required = True
                break
            else:
                print("Interface does not exist")
                continue

        while True:
            user_input = input(
                "Configure an infrastructure VLAN [y/N]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input.lower() == 'y':
                while True:
                    user_input = input(
                        "Infrastructure VLAN Identifier [" +
                        str(self.infrastructure_vlan) + "]: ")
                    if user_input.lower() == 'q':
                        raise UserQuit
                    elif is_valid_vlan(user_input):
                        if user_input == self.management_vlan:
                            print(textwrap.fill(
                                "Invalid VLAN Identifier. Configured VLAN "
                                "Identifier is already in use by another "
                                "network.", 80))
                            continue
                        self.infrastructure_vlan = user_input
                        self.infrastructure_interface_name = \
                            self.infrastructure_interface + '.' + \
                            self.infrastructure_vlan
                        break
                    else:
                        print("VLAN is invalid/unsupported")
                        continue
                break
            elif user_input.lower() in ('n', ''):
                if infra_vlan_required:
                    print(textwrap.fill(
                        "An infrastructure VLAN is required since the "
                        "configured infrastructure interface is the "
                        "same as the configured management or external "
                        "OAM interface.", 80))
                    continue
                self.infrastructure_vlan = ""
                break
            else:
                print("Invalid choice")
                continue

        while True:
            user_input = input("Infrastructure interface MTU [" +
                               str(self.infrastructure_mtu) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == "":
                user_input = self.infrastructure_mtu

            if (self.management_interface_configured and
                    self.infrastructure_interface ==
                    self.management_interface and
                    self.infrastructure_vlan and
                    user_input > self.management_mtu):
                print("Infrastructure VLAN MTU must not be larger than "
                      "underlying management interface MTU")
                continue
            elif is_mtu_valid(user_input):
                self.infrastructure_mtu = user_input
                break
            else:
                print("MTU is invalid/unsupported")
                continue

        while True:
            if not self.lag_infrastructure_interface:
                break
            print('')
            print("Specify one of the bonding policies. Possible values are:")
            print("  1) Active-backup policy")
            print("  2) Balanced XOR policy")
            print("  3) 802.3ad (LACP) policy")

            user_input = input(
                "\nInfrastructure interface bonding policy [" +
                str(self.lag_infrastructure_interface_policy) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == '1':
                self.lag_infrastructure_interface_policy = \
                    constants.LAG_MODE_ACTIVE_BACKUP
                self.lag_infrastructure_interface_txhash = None
                break
            elif user_input == '2':
                self.lag_infrastructure_interface_policy = \
                    constants.LAG_MODE_BALANCE_XOR
                self.lag_infrastructure_interface_txhash = \
                    constants.LAG_TXHASH_LAYER2
                break
            elif user_input == '3':
                self.lag_infrastructure_interface_policy = \
                    constants.LAG_MODE_8023AD
                self.lag_infrastructure_interface_txhash = \
                    constants.LAG_TXHASH_LAYER2
                break
            elif user_input == "":
                break
            else:
                print("Invalid choice")
                continue

        while True:
            if not self.lag_infrastructure_interface:
                break

            print(textwrap.fill(
                "A maximum of 2 physical interfaces can be attached to the "
                "infrastructure interface.", 80))
            print('')

            user_input = input(
                "First infrastructure interface member [" +
                str(self.lag_infrastructure_interface_member0) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == "":
                user_input = self.lag_infrastructure_interface_member0

            if self.is_interface_in_bond(user_input):
                print(textwrap.fill(
                    "Interface is already configured as part of an "
                    "aggregated interface.", 80))
                continue
            elif self.is_interface_in_use(user_input):
                print("Interface is already in use")
                continue
            elif interface_exists(user_input):
                self.lag_infrastructure_interface_member0 = user_input
            else:
                print("Interface does not exist")
                self.lag_infrastructure_interface_member0 = ""
                continue

            user_input = input(
                "Second infrastructure interface member [" +
                str(self.lag_infrastructure_interface_member1) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == "":
                user_input = self.lag_infrastructure_interface_member1

            if self.is_interface_in_bond(user_input):
                print(textwrap.fill(
                    "Interface is already configured as part of an "
                    "aggregated interface.", 80))
                continue
            elif self.is_interface_in_use(user_input):
                print("Interface is already in use")
                continue
            elif interface_exists(user_input):
                if user_input == self.lag_infrastructure_interface_member0:
                    print("Cannot use member 0 as member 1")
                    continue
                else:
                    self.lag_infrastructure_interface_member1 = user_input
                    break
            else:
                print("Interface does not exist")
                self.lag_infrastructure_interface_member1 = ""
                user_input = input(
                    "Do you want a single physical member in the bond "
                    "interface [y/n]: ")
                if user_input.lower() == 'q':
                    raise UserQuit
                elif user_input.lower() == 'y':
                    break
                elif user_input.lower() in ('n', ''):
                    continue
                else:
                    print("Invalid choice")
                    continue

        min_addresses = 8
        while True:
            user_input = input("Infrastructure subnet [" +
                               str(self.infrastructure_subnet) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == "":
                user_input = self.infrastructure_subnet

            try:
                ip_input = IPNetwork(user_input)
                if ip_input.ip != ip_input.network:
                    print("Invalid network address")
                    continue
                elif ip_input.version != self.management_subnet.version:
                    print("IP version must match management network")
                    continue
                elif ip_input.size < min_addresses:
                    print("Infrastructure subnet too small - "
                          "must have at least 16 addresses")
                    continue
                elif ip_input.version == 6 and ip_input.prefixlen < 64:
                    print("IPv6 minimum prefix length is 64")
                    continue
                elif ((self.separate_pxeboot_network and
                       ip_input.ip in self.pxeboot_subnet) or
                      ip_input.ip in self.management_subnet):
                    print("Infrastructure subnet overlaps with an already "
                          "configured subnet")
                    continue

                if ip_input.size < 255:
                    print("WARNING: Subnet allows only %d addresses."
                          % ip_input.size)

                self.infrastructure_subnet = ip_input
                break
            except AddrFormatError:
                print("Invalid subnet - please enter a valid IPv4 subnet")

        self.infrastructure_start_address = \
            self.infrastructure_subnet[2]
        self.infrastructure_end_address = \
            self.infrastructure_subnet[-2]
        while True:
            user_input = input(
                "Use entire infrastructure subnet [Y/n]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input.lower() == 'y':
                self.use_entire_infra_subnet = True
                break
            elif user_input.lower() == 'n':
                self.use_entire_infra_subnet = False
                break
            elif user_input == "":
                break
            else:
                print("Invalid choice")
                continue

        if not self.use_entire_infra_subnet:
            while True:
                while True:
                    user_input = input(
                        "Infrastructure network start address [" +
                        str(self.infrastructure_start_address) + "]: ")
                    if user_input.lower() == 'q':
                        raise UserQuit
                    elif user_input == "":
                        user_input = self.infrastructure_start_address

                    try:
                        self.infrastructure_start_address = \
                            validate_address_str(
                                user_input, self.infrastructure_subnet)
                        break
                    except ValidateFail as e:
                        print("Invalid start address. \n Reason: %s" % e)

                while True:
                    user_input = input(
                        "Infrastructure network end address [" +
                        str(self.infrastructure_end_address) + "]: ")
                    if user_input.lower() == 'q':
                        raise UserQuit
                    elif user_input == "":
                        user_input = self.infrastructure_end_address

                    try:
                        self.infrastructure_end_address = validate_address_str(
                            user_input, self.infrastructure_subnet)
                        break
                    except ValidateFail as e:
                        print("Invalid infrastructure end address. \n"
                              "Reason: %s" % e)

                if not self.infrastructure_start_address < \
                        self.infrastructure_end_address:
                    print("Start address not less than end address. ")
                    print('')
                    continue

                address_range = IPRange(str(self.infrastructure_start_address),
                                        str(self.infrastructure_end_address))
                if not address_range.size >= min_addresses:
                    print(
                        "Address range must contain at least %d addresses. " %
                        min_addresses)
                    continue
                break

        default_controller0_infra_ip = self.infrastructure_start_address + 1
        ip_input = IPAddress(default_controller0_infra_ip)
        if not self.is_valid_infrastructure_address(ip_input):
            raise ConfigFail("Unable to create controller-0 Infrastructure "
                             "address")
        self.controller_infrastructure_address_0 = ip_input
        default_controller1_infra_ip = \
            self.controller_infrastructure_address_0 + 1
        ip_input = IPAddress(default_controller1_infra_ip)
        if not self.is_valid_infrastructure_address(ip_input):
            raise ConfigFail("Unable to create controller-1 Infrastructure "
                             "address")
        self.controller_infrastructure_address_1 = ip_input
        first_nfs_ip = self.controller_infrastructure_address_1 + 1

        """ create default Infrastructure NFS address """
        default_nfs_ip = IPAddress(first_nfs_ip)
        if not self.is_valid_infrastructure_address(default_nfs_ip):
            raise ConfigFail("Unable to create NFS Infrastructure address 1")
        self.nfs_infrastructure_address_1 = default_nfs_ip

        """ Infrastructure interface configuration complete"""
        self.infrastructure_interface_configured = True

    def is_valid_external_oam_subnet(self, ip_subnet):
        """Determine whether an OAM subnet is valid."""
        if ip_subnet.size < 8:
            print("Subnet too small - must have at least 8 addresses")
            return False
        elif ip_subnet.ip != ip_subnet.network:
            print("Invalid network address")
            return False
        elif ip_subnet.version == 6 and ip_subnet.prefixlen < 64:
            print("IPv6 minimum prefix length is 64")
            return False
        elif ip_subnet.is_multicast():
            print("Invalid network address - multicast address not allowed")
            return False
        elif ip_subnet.is_loopback():
            print("Invalid network address - loopback address not allowed")
            return False
        elif ((self.separate_pxeboot_network and
                ip_subnet.ip in self.pxeboot_subnet) or
                (ip_subnet.ip in self.management_subnet) or
                (self.infrastructure_interface and
                 ip_subnet.ip in self.infrastructure_subnet)):
            print("External OAM subnet overlaps with an already "
                  "configured subnet")
            return False
        else:
            return True

    def is_valid_external_oam_address(self, ip_address):
        """Determine whether an OAM address is valid."""
        if ip_address == self.external_oam_subnet.network:
            print("Cannot use network address")
            return False
        elif ip_address == self.external_oam_subnet.broadcast:
            print("Cannot use broadcast address")
            return False
        elif ip_address.is_multicast():
            print("Invalid network address - multicast address not allowed")
            return False
        elif ip_address.is_loopback():
            print("Invalid network address - loopback address not allowed")
            return False
        elif ip_address not in self.external_oam_subnet:
            print("Address must be in the external OAM subnet")
            return False
        else:
            return True

    def input_aio_simplex_oam_ip_address(self):
        """Allow user to input external OAM IP and perform validation."""
        while True:
            user_input = input(
                "External OAM address [" +
                str(self.external_oam_gateway_address + 1) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == "":
                user_input = self.external_oam_gateway_address + 1

            try:
                ip_input = IPAddress(user_input)
                if not self.is_valid_external_oam_address(ip_input):
                    continue
                self.external_oam_floating_address = ip_input
                self.external_oam_address_0 = ip_input
                self.external_oam_address_1 = ip_input
                break
            except (AddrFormatError, ValueError):
                print("Invalid address - "
                      "please enter a valid %s address" %
                      ip_version_to_string(self.external_oam_subnet.version)
                      )

    def input_oam_ip_address(self):
        """Allow user to input external OAM IP and perform validation."""
        while True:
            user_input = input(
                "External OAM floating address [" +
                str(self.external_oam_gateway_address + 1) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == "":
                user_input = self.external_oam_gateway_address + 1

            try:
                ip_input = IPAddress(user_input)
                if not self.is_valid_external_oam_address(ip_input):
                    continue
                self.external_oam_floating_address = ip_input
                break
            except (AddrFormatError, ValueError):
                print("Invalid address - "
                      "please enter a valid %s address" %
                      ip_version_to_string(self.external_oam_subnet.version)
                      )

        while True:
            user_input = input("External OAM address for first "
                               "controller node [" +
                               str(self.external_oam_floating_address + 1)
                               + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == "":
                user_input = self.external_oam_floating_address + 1

            try:
                ip_input = IPAddress(user_input)
                if not self.is_valid_external_oam_address(ip_input):
                    continue
                self.external_oam_address_0 = ip_input
                break
            except (AddrFormatError, ValueError):
                print("Invalid address - "
                      "please enter a valid %s address" %
                      ip_version_to_string(self.external_oam_subnet.version)
                      )

        while True:
            user_input = input("External OAM address for second "
                               "controller node [" +
                               str(self.external_oam_address_0 + 1) +
                               "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == "":
                user_input = self.external_oam_address_0 + 1

            try:
                ip_input = IPAddress(user_input)
                if not self.is_valid_external_oam_address(ip_input):
                    continue
                self.external_oam_address_1 = ip_input
                break
            except (AddrFormatError, ValueError):
                print("Invalid address - "
                      "please enter a valid %s address" %
                      ip_version_to_string(self.external_oam_subnet.version)
                      )

    def input_external_oam_config(self):
        """Allow user to input external OAM config and perform validation."""

        print("\nExternal OAM Network:")
        print("---------------------\n")
        print(textwrap.fill(
              "The external OAM network is used for management of the "
              "cloud. It also provides access to the "
              "platform APIs. IP addresses on this network are reachable "
              "outside the data center.", 80))
        print('')

        ext_oam_vlan_required = False

        while True:
            print(textwrap.fill(
                "An external OAM bond interface provides redundant "
                "connections for the OAM network.", 80))
            print('')
            user_input = input(
                "External OAM interface link aggregation [y/N]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input.lower() == 'y':
                self.lag_external_oam_interface = True
                break
            elif user_input.lower() == 'n':
                self.lag_external_oam_interface = False
                break
            elif user_input == "":
                break
            else:
                print("Invalid choice")
                continue

        while True:
            if self.lag_external_oam_interface:
                self.external_oam_interface = self.get_next_lag_name()

            user_input = input("External OAM interface [" +
                               str(self.external_oam_interface) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == "":
                user_input = self.external_oam_interface
            elif self.lag_external_oam_interface:
                print(textwrap.fill(
                    "Warning: The default name for the external OAM bond "
                    "interface (%s) cannot be changed." %
                    self.external_oam_interface, 80))
                print('')
                user_input = self.external_oam_interface

            if self.is_interface_in_bond(user_input):
                print(textwrap.fill(
                    "Interface is already configured as part of an "
                    "aggregated interface.", 80))
                continue
            elif self.lag_external_oam_interface:
                self.external_oam_interface = user_input
                self.external_oam_interface_name = user_input
                break
            elif (interface_exists(user_input) or
                  user_input == self.management_interface or
                  user_input == self.infrastructure_interface):
                self.external_oam_interface = user_input
                self.external_oam_interface_name = user_input
                if ((self.management_interface_configured and
                     user_input == self.management_interface) or
                    (self.infrastructure_interface_configured and
                     user_input == self.infrastructure_interface and
                     not self.infrastructure_vlan)):
                    ext_oam_vlan_required = True
                break
            else:
                print("Interface does not exist")
                continue

        while True:
            user_input = input(
                "Configure an external OAM VLAN [y/N]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input.lower() == 'y':
                while True:
                    user_input = input(
                        "External OAM VLAN Identifier [" +
                        str(self.external_oam_vlan) + "]: ")
                    if user_input.lower() == 'q':
                        raise UserQuit
                    elif is_valid_vlan(user_input):
                        if ((user_input == self.management_vlan) or
                                (user_input == self.infrastructure_vlan)):
                            print(textwrap.fill(
                                "Invalid VLAN Identifier. Configured VLAN "
                                "Identifier is already in use by another "
                                "network.", 80))
                            continue
                        self.external_oam_vlan = user_input
                        self.external_oam_interface_name = \
                            self.external_oam_interface + '.' + \
                            self.external_oam_vlan
                        break
                    else:
                        print("VLAN is invalid/unsupported")
                        continue
                break
            elif user_input.lower() in ('n', ''):
                if ext_oam_vlan_required:
                    print(textwrap.fill(
                        "An external oam VLAN is required since the "
                        "configured external oam interface is the "
                        "same as either the configured management "
                        "or infrastructure interface.", 80))
                    continue
                self.external_oam_vlan = ""
                break
            else:
                print("Invalid choice")
                continue

        while True:
            user_input = input("External OAM interface MTU [" +
                               str(self.external_oam_mtu) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == "":
                user_input = self.external_oam_mtu

            if (self.management_interface_configured and
                    self.external_oam_interface ==
                    self.management_interface and
                    self.external_oam_vlan and
                    user_input > self.management_mtu):
                print("External OAM VLAN MTU must not be larger than "
                      "underlying management interface MTU")
                continue
            elif (self.infrastructure_interface_configured and
                    self.external_oam_interface ==
                    self.infrastructure_interface and
                    self.external_oam_vlan and
                    user_input > self.infrastructure_mtu):
                print("External OAM VLAN MTU must not be larger than "
                      "underlying infrastructure interface MTU")
                continue
            elif (self.infrastructure_interface_configured and
                    self.external_oam_interface ==
                    self.infrastructure_interface and
                    self.infrastructure_vlan and
                    not self.external_oam_vlan and
                    user_input < self.infrastructure_mtu):
                print("External OAM interface MTU must not be smaller than "
                      "infrastructure VLAN interface MTU")
                continue
            elif is_mtu_valid(user_input):
                self.external_oam_mtu = user_input
                break
            else:
                print("MTU is invalid/unsupported")
                continue

        while True:
            if not self.lag_external_oam_interface:
                break

            print('')
            print("Specify one of the bonding policies. Possible values are:")
            print("  1) Active-backup policy")
            print("  2) Balanced XOR policy")
            print("  3) 802.3ad (LACP) policy")

            user_input = input(
                "\nExternal OAM interface bonding policy [" +
                str(self.lag_external_oam_interface_policy) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == '1':
                self.lag_external_oam_interface_policy = \
                    constants.LAG_MODE_ACTIVE_BACKUP
                break
            elif user_input == '2':
                self.lag_external_oam_interface_policy = \
                    constants.LAG_MODE_BALANCE_XOR
                self.lag_external_oam_interface_txhash = \
                    constants.LAG_TXHASH_LAYER2
                break
            elif user_input == '3':
                self.lag_external_oam_interface_policy = \
                    constants.LAG_MODE_8023AD
                self.lag_external_oam_interface_txhash = \
                    constants.LAG_TXHASH_LAYER2
                break
            elif user_input == "":
                break
            else:
                print("Invalid choice")
                continue

        while True:
            if not self.lag_external_oam_interface:
                break

            print(textwrap.fill(
                "A maximum of 2 physical interfaces can be attached to the "
                "external OAM interface.", 80))
            print('')

            user_input = input(
                "First external OAM interface member [" +
                str(self.lag_external_oam_interface_member0) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == "":
                user_input = self.lag_external_oam_interface_member0

            if self.is_interface_in_bond(user_input):
                print(textwrap.fill(
                    "Interface is already configured as part of an "
                    "aggregated interface.", 80))
                continue
            elif self.is_interface_in_use(user_input):
                print("Interface is already in use")
                continue
            elif interface_exists(user_input):
                self.lag_external_oam_interface_member0 = user_input
            else:
                print("Interface does not exist")
                self.lag_external_oam_interface_member0 = ""
                continue

            user_input = input(
                "Second external oam interface member [" +
                str(self.lag_external_oam_interface_member1) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == "":
                user_input = self.lag_external_oam_interface_member1

            if self.is_interface_in_bond(user_input):
                print(textwrap.fill(
                    "Interface is already configured as part of an "
                    "aggregated interface.", 80))
                continue
            elif self.is_interface_in_use(user_input):
                print("Interface is already in use")
                continue
            elif user_input == self.lag_external_oam_interface_member0:
                print("Cannot use member 0 as member 1")
                continue
            if interface_exists(user_input):
                self.lag_external_oam_interface_member1 = user_input
                break
            else:
                print("Interface does not exist")
                self.lag_external_oam_interface_member1 = ""
                user_input = input(
                    "Do you want a single physical member in the bond "
                    "interface [y/n]: ")
                if user_input.lower() == 'q':
                    raise UserQuit
                elif user_input.lower() == 'y':
                    break
                elif user_input.lower() == 'n':
                    continue

        while True:
            user_input = input("External OAM subnet [" +
                               str(self.external_oam_subnet) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == "":
                user_input = self.external_oam_subnet

            try:
                ip_input = IPNetwork(user_input)
                if not self.is_valid_external_oam_subnet(ip_input):
                    continue
                self.external_oam_subnet = ip_input
                break
            except AddrFormatError:
                print("Invalid subnet - "
                      "please enter a valid IPv4 or IPv6 subnet"
                      )

        while True:
            user_input = input("External OAM gateway address [" +
                               str(self.external_oam_subnet[1]) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == "":
                user_input = self.external_oam_subnet[1]

            try:
                ip_input = IPAddress(user_input)
                if not self.is_valid_external_oam_address(ip_input):
                    continue
                self.external_oam_gateway_address = ip_input
                break
            except (AddrFormatError, ValueError):
                print("Invalid address - "
                      "please enter a valid %s address" %
                      ip_version_to_string(self.external_oam_subnet.version)
                      )

        if self.system_mode == sysinv_constants.SYSTEM_MODE_SIMPLEX:
            self.input_aio_simplex_oam_ip_address()
        else:
            self.input_oam_ip_address()

        """ External OAM interface configuration complete"""
        self.external_oam_interface_configured = True

    def is_valid_cluster_host_address(self, ip_address):
        """Determine whether cluster host address is valid."""
        if ip_address == self.cluster_host_subnet.network:
            print("Cannot use network address")
            return False
        elif ip_address == self.cluster_host_subnet.broadcast:
            print("Cannot use broadcast address")
            return False
        elif ip_address.is_multicast():
            print("Invalid network address - multicast address not allowed")
            return False
        elif ip_address.is_loopback():
            print("Invalid network address - loopback address not allowed")
            return False
        elif ip_address not in self.cluster_host_subnet:
            print("Address must be in the cluster host subnet")
            return False
        else:
            return True

    def input_cluster_host_config(self):
        """Allow user to input cluster-host config and perform validation."""

        print("\nCluster Host Network:")
        print("-----------------------\n")

        print((textwrap.fill(
            "The cluster host network is used for internal communication "
            "between Kubernetes clusters. "
            "IP addresses on this network are reachable only within the data "
            "center.", 80)))
        print('')
        print(textwrap.fill(
            "If a separate cluster host interface is not configured the "
            "management network will be used.", 80))
        print('')

        while True:
            print('')
            print(textwrap.fill(
                "An cluster host bond interface provides redundant "
                "connections for the cluster host network.", 80))
            print('')
            user_input = input(
                "Cluster host interface link aggregation [y/N]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input.lower() == 'y':
                self.lag_cluster_host_interface = True
                break
            elif user_input.lower() in ('n', ''):
                self.lag_cluster_host_interface = False
                break
            else:
                print("Invalid choice")
                continue

        while True:
            if self.lag_cluster_host_interface:
                self.cluster_host_interface = self.get_next_lag_name()

            user_input = input("Cluster host interface [" +
                               str(self.management_interface) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == '':
                user_input = self.management_interface
                if user_input == '':
                    print("Invalid interface")
                    continue
            elif self.lag_cluster_host_interface:
                print(textwrap.fill(
                    "Warning: The default name for the cluster host bond "
                    "interface (%s) cannot be changed." %
                    self.cluster_host_interface, 80))
                print('')
                user_input = self.cluster_host_interface

            if self.is_interface_in_bond(user_input):
                print(textwrap.fill(
                    "Interface is already configured as part of an "
                    "aggregated interface.", 80))
                continue
            elif self.lag_cluster_host_interface:
                self.cluster_host_interface = user_input
                self.cluster_host_interface_name = user_input
                break
            elif interface_exists(user_input):
                self.cluster_host_interface = user_input
                self.cluster_host_interface_name = user_input
                break
            else:
                print("Interface does not exist")
                continue

        while True:
            user_input = input(
                "Configure a cluster host VLAN [y/N]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input.lower() == 'y':
                while True:
                    user_input = input(
                        "Cluster host VLAN Identifier [" +
                        str(self.cluster_host_vlan) + "]: ")
                    if user_input.lower() == 'q':
                        raise UserQuit
                    elif is_valid_vlan(user_input):
                        self.cluster_host_vlan = user_input
                        self.cluster_host_interface_name = \
                            self.cluster_host_interface + '.' + \
                            self.cluster_host_vlan
                        break
                    else:
                        print("VLAN is invalid/unsupported")
                        continue
                break
            elif user_input.lower() in ('n', ''):
                self.cluster_host_vlan = ""
                break
            else:
                print("Invalid choice")
                continue

        while True:
            if self.cluster_host_interface == self.management_interface:
                break
            user_input = input("Cluster host interface MTU [" +
                               str(self.cluster_host_mtu) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == "":
                user_input = self.cluster_host_mtu

            if (self.management_interface_configured and
                    self.cluster_host_interface ==
                    self.management_interface and
                    self.cluster_host_vlan and
                    user_input > self.management_mtu):
                print("Cluster host VLAN MTU must not be larger than "
                      "underlying management interface MTU")
                continue
            elif is_mtu_valid(user_input):
                self.cluster_host_mtu = user_input
                break
            else:
                print("MTU is invalid/unsupported")
                continue

        while True:
            if self.cluster_host_interface == self.management_interface:
                break
            if not self.lag_cluster_host_interface:
                break
            print('')
            print("Specify one of the bonding policies. Possible values are:")
            print("  1) Active-backup policy")
            print("  2) Balanced XOR policy")
            print("  3) 802.3ad (LACP) policy")

            user_input = input(
                "\nCluster host interface bonding policy [" +
                str(self.lag_cluster_host_interface_policy) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == '1':
                self.lag_cluster_host_interface_policy = \
                    constants.LAG_MODE_ACTIVE_BACKUP
                self.lag_cluster_host_interface_txhash = None
                break
            elif user_input == '2':
                self.lag_cluster_host_interface_policy = \
                    constants.LAG_MODE_BALANCE_XOR
                self.lag_cluster_host_interface_txhash = \
                    constants.LAG_TXHASH_LAYER2
                break
            elif user_input == '3':
                self.lag_cluster_host_interface_policy = \
                    constants.LAG_MODE_8023AD
                self.lag_cluster_host_interface_txhash = \
                    constants.LAG_TXHASH_LAYER2
                break
            elif user_input == "":
                break
            else:
                print("Invalid choice")
                continue

        while True:
            if not self.lag_cluster_host_interface:
                break
            if self.cluster_host_interface == self.management_interface:
                    break

            print(textwrap.fill(
                "A maximum of 2 physical interfaces can be attached to the "
                "cluster host interface.", 80))
            print('')

            user_input = input(
                "First cluster host interface member [" +
                str(self.lag_cluster_host_interface_member0) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == "":
                user_input = self.lag_cluster_host_interface_member0

            if self.is_interface_in_bond(user_input):
                print(textwrap.fill(
                    "Interface is already configured as part of an "
                    "aggregated interface.", 80))
                continue
            elif self.is_interface_in_use(user_input):
                print("Interface is already in use")
                continue
            elif interface_exists(user_input):
                self.lag_cluster_host_interface_member0 = user_input
            else:
                print("Interface does not exist")
                self.lag_cluster_host_interface_member0 = ""
                continue

            user_input = input(
                "Second cluster host interface member [" +
                str(self.lag_cluster_host_interface_member1) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == "":
                user_input = self.lag_cluster_host_interface_member1

            if self.is_interface_in_bond(user_input):
                print(textwrap.fill(
                    "Interface is already configured as part of an "
                    "aggregated interface.", 80))
                continue
            elif self.is_interface_in_use(user_input):
                print("Interface is already in use")
                continue
            elif interface_exists(user_input):
                if user_input == self.lag_cluster_host_interface_member0:
                    print("Cannot use member 0 as member 1")
                    continue
                else:
                    self.lag_cluster_host_interface_member1 = user_input
                    break
            else:
                print("Interface does not exist")
                self.lag_cluster_host_interface_member1 = ""
                user_input = input(
                    "Do you want a single physical member in the bond "
                    "interface [y/n]: ")
                if user_input.lower() == 'q':
                    raise UserQuit
                elif user_input.lower() == 'y':
                    break
                elif user_input.lower() in ('n', ''):
                    continue
                else:
                    print("Invalid choice")
                    continue

        min_addresses = 8
        while True:
            user_input = input("Cluster subnet [" +
                               str(self.cluster_host_subnet) + "]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input == "":
                user_input = self.cluster_host_subnet

            try:
                ip_input = IPNetwork(user_input)
                if ip_input.ip != ip_input.network:
                    print("Invalid network address")
                    continue
                elif ip_input.size < min_addresses:
                    print("Cluster subnet too small - "
                          "must have at least 16 addresses")
                    continue
                elif ip_input.version == 6 and ip_input.prefixlen < 64:
                    print("IPv6 minimum prefix length is 64")
                    continue
                elif ((self.separate_pxeboot_network and
                       ip_input.ip in self.pxeboot_subnet) or
                      ip_input.ip in self.management_subnet):
                    print("Cluster host subnet overlaps with an already "
                          "configured subnet")
                    continue

                if ip_input.size < 255:
                    print("WARNING: Subnet allows only %d addresses."
                          % ip_input.size)

                self.cluster_host_subnet = ip_input
                break
            except AddrFormatError:
                print("Invalid subnet - please enter a valid IPv4 subnet")

        """ Cluster host interface configuration complete"""
        self.cluster_host_interface_configured = True

    def get_dns_servers(self):
        """Produce a comma separated list of DNS servers."""
        servers = [str(s) for s in self.nameserver_addresses if s]
        return ",".join(servers)

    def input_dns_config(self):
        """Allow user to input DNS config and perform validation."""

        print("\nDomain Name System (DNS):")
        print("-------------------------\n")
        print(textwrap.fill(
            "Configuring DNS servers accessible through the external "
            "OAM network allows domain names to be mapped to IP "
            "addresses.", 80))
        print(textwrap.fill(
            "The configuration of at least one DNS server is mandatory. To "
            "skip the configuration of one or more nameservers (1 to 3 are "
            "allowed), enter C to continue to the next configuration item.",
            80))
        print('')

        if self.external_oam_subnet.version == 6:
            self.nameserver_addresses = ["2001:4860:4860::8888",
                                         "2001:4860:4860::8844", ""]

        for server in range(0, len(self.nameserver_addresses)):
            while True:
                user_input = raw_input(
                    "Nameserver " + str(server + 1) + " [" +
                    str(self.nameserver_addresses[server]) + "]: ")
                if user_input.lower() == 'q':
                    raise UserQuit
                elif user_input.lower() == 'c':
                    if server == 0:
                        print("At least one DNS server is required.")
                        continue
                    for x in range(server, len(self.nameserver_addresses)):
                        self.nameserver_addresses[x] = ""
                    return
                elif user_input == "":
                    user_input = self.nameserver_addresses[server]
                    # Pressing enter with a blank default will continue
                    if user_input == "":
                        return

                try:
                    try:
                        ip_input = validate_nameserver_address_str(
                            user_input, self.external_oam_subnet.version)
                    except ValidateFail as e:
                        print('{}'.format(e))
                        continue
                    self.nameserver_addresses[server] = ip_input
                    break
                except (AddrFormatError, ValueError):
                    print("Invalid address - please enter a valid IPv4 "
                          "address")

    def input_docker_proxy_config(self):
        """Allow user to input docker proxy config."""

        print("\nDocker Proxy:")
        print("-------------\n")
        print(textwrap.fill(
              "Docker proxy is needed if host OAM network is behind a proxy.",
              80))
        print('')
        while True:
            user_input = input(
                "Configure docker proxy [y/N]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input.lower() == 'y':
                while True:
                    user_input = input(
                        "HTTP proxy (http://example.proxy:port): ")
                    if user_input.lower() == 'q':
                        raise UserQuit
                    if user_input:
                        if is_valid_url(user_input):
                            self.docker_http_proxy = user_input
                            break
                        else:
                            print("Please enter a valid url")
                            continue
                    else:
                        self.docker_http_proxy = ""
                        break

                while True:
                    user_input = input(
                        "HTTPS proxy (https://example.proxy:port): ")
                    if user_input.lower() == 'q':
                        raise UserQuit
                    if user_input:
                        if is_valid_url(user_input):
                            self.docker_https_proxy = user_input
                            break
                        else:
                            print("Please enter a valid url")
                            continue
                    else:
                        self.docker_https_proxy = ""
                        break

                if not self.docker_http_proxy and not self.docker_https_proxy:
                    print("At least one proxy required")
                    continue
                else:
                    self.enable_docker_proxy = True

                while True:
                    # TODO: Current Docker version 18.03.1-ce utilizes go-lang
                    # net library for proxy setting. The go-lang net lib
                    # doesn't support CIDR notation until this commit:
                    #
                    # https://github.com/golang/net/commit/
                    #     c21de06aaf072cea07f3a65d6970e5c7d8b6cd6d
                    #
                    # After docker upgrades to a version that CIDR notation
                    # supported pre_set_no_proxy will be simplified to subnets
                    if self.system_mode == \
                            sysinv_constants.SYSTEM_MODE_SIMPLEX:
                        pre_set_no_proxy = "localhost,127.0.0.1," + \
                            str(self.controller_floating_address) + "," + \
                            str(self.controller_address_0) + "," + \
                            str(self.controller_address_1) + "," + \
                            str(self.external_oam_address_0)
                    else:
                        pre_set_no_proxy = "localhost,127.0.0.1," + \
                            str(self.controller_floating_address) + "," + \
                            str(self.controller_address_0) + "," + \
                            str(self.controller_address_1) + "," + \
                            str(self.external_oam_floating_address) + "," + \
                            str(self.external_oam_address_0) + "," + \
                            str(self.external_oam_address_1)

                    user_input = input(
                        "Additional NO proxy besides '" +
                        pre_set_no_proxy +
                        "'\n(Comma-separated addresses, " +
                        "wildcard/subnet not allowed)\n:")
                    if user_input.lower() == 'q':
                        raise UserQuit
                    if user_input:
                        input_addr_list = user_input.split(",")
                        valid_address = True
                        for input_addr in input_addr_list:
                            if not is_valid_domain_or_ip(input_addr):
                                print("Input address '%s' is invalid" %
                                      input_addr)
                                valid_address = False
                                break
                        if valid_address:
                            self.docker_no_proxy = pre_set_no_proxy + \
                                "," + user_input
                            break
                        else:
                            continue
                    else:
                        self.docker_no_proxy = pre_set_no_proxy
                        break
                break
            elif user_input.lower() in ('n', ''):
                self.enable_docker_proxy = False
                break
            else:
                print("Invalid choice")
                continue

    def input_docker_registry_config(self):
        """Allow user to input docker registry config."""

        print("\nDocker Registry:")
        print("----------------\n")
        print("Configure docker registries to pull images from.\n"
              "Default registries are:\n"
              "k8s.gcr.io, gcr.io, quay.io, docker.io\n"
              )
        while True:
            user_input = input(
                "Use default docker registries [Y/n]: ")
            if user_input.lower() == 'q':
                raise UserQuit
            elif user_input.lower() == 'n':
                # unexpected newline displayed if textwrap.fill with
                # '\n' included
                print("\nEach registry can be specified as one of the"
                      "following:\n"
                      " - domain (e.g. example.domain)\n"
                      " - domain with port (e.g. example.domain:5000)\n"
                      " - IPv4 address (e.g. 1.2.3.4)\n"
                      " - IPv4 address with port (e.g. 1.2.3.4:5000)\n"
                      )
                while True:
                    user_input = input(
                        "Use a unified registry replacing all "
                        "default registries [y/n]: ")
                    if user_input.lower() == 'q':
                        raise UserQuit
                    elif user_input.lower() == 'y':
                        # Input a unified registry to avoid
                        # inputing the same registry repeatly
                        while True:
                            user_input = input(
                                "Enter a unified registry: ")
                            if user_input.lower() == 'q':
                                raise UserQuit
                            if is_valid_domain_or_ip(user_input):
                                self.docker_k8s_registry = user_input
                                self.docker_gcr_registry = user_input
                                self.docker_quay_registry = user_input
                                self.docker_docker_registry = user_input
                                self.docker_use_default_registry = False
                                break
                            else:
                                print("Please enter a valid registry address")
                                continue

                        # Only if a unified registry set, it could be
                        # an insecure registry
                        while True:
                            user_input = input(
                                "Is '" + self.docker_k8s_registry +
                                "' a secure registry (https) [Y/n]: ")
                            if user_input.lower() == 'q':
                                raise UserQuit
                            elif user_input.lower() in ('y', ''):
                                self.is_secure_registry = True
                                break
                            elif user_input.lower() == 'n':
                                self.is_secure_registry = False
                                break
                            else:
                                print("Invalid choice")
                                continue
                        break

                    elif user_input.lower() == 'n':
                        # Input alternative registries separately
                        while True:
                            user_input = input(
                                "Alternative registry to k8s.gcr.io: ")
                            if user_input.lower() == 'q':
                                raise UserQuit
                            if is_valid_domain_or_ip(user_input):
                                self.docker_k8s_registry = user_input
                                break
                            else:
                                print("Please enter a valid registry address")
                                continue

                        while True:
                            user_input = input(
                                "Alternative registry to gcr.io: ")
                            if user_input.lower() == 'q':
                                raise UserQuit
                            if is_valid_domain_or_ip(user_input):
                                self.docker_gcr_registry = user_input
                                break
                            else:
                                print("Please enter a valid registry address")
                                continue

                        while True:
                            user_input = input(
                                "Alternative registry to quay.io: ")
                            if user_input.lower() == 'q':
                                raise UserQuit
                            if is_valid_domain_or_ip(user_input):
                                self.docker_quay_registry = user_input
                                break
                            else:
                                print("Please enter a valid registry address")
                                continue

                        while True:
                            user_input = input(
                                "Alternative registry to docker.io: ")
                            if user_input.lower() == 'q':
                                raise UserQuit
                            if is_valid_domain_or_ip(user_input):
                                self.docker_docker_registry = user_input
                                break
                            else:
                                print("Please enter a valid registry address")
                                continue

                        if (self.docker_k8s_registry or
                                self.docker_gcr_registry or
                                self.docker_quay_registry or
                                self.docker_docker_registry):
                            self.docker_use_default_registry = False
                            break
                        else:
                            print("At least one registry is required")
                            continue
                    else:
                        print("Invalid choice")
                        continue
                break

            elif user_input.lower() in ('y', ''):
                self.docker_use_default_registry = True
                break
            else:
                print("Invalid choice")
                continue

    def input_authentication_config(self):
        """Allow user to input authentication config and perform validation.
        """

        print("\nCloud Authentication:")
        print("-------------------------------\n")
        print(textwrap.fill(
            "Configure a password for the Cloud admin user "
            "The Password must have a minimum length of 7 character, "
            "and conform to password complexity rules", 80))

        password_input = ""
        while True:
            user_input = getpass.getpass("Create admin user password: ")
            if user_input.lower() == 'q':
                raise UserQuit

            password_input = user_input
            if len(password_input) < 1:
                print("Password cannot be empty")
                continue

            user_input = getpass.getpass("Repeat admin user password: ")
            if user_input.lower() == 'q':
                raise UserQuit

            if user_input != password_input:
                print("Password did not match")
                continue
            else:
                print("\n")
                self.admin_password = user_input
                # the admin password will be validated
                self.add_password_for_validation('ADMIN_PASSWORD',
                                                 self.admin_password)
                if self.process_validation_passwords(console=True):
                    break

    def default_config(self):
        """Use default configuration suitable for testing in virtual env."""

        self.admin_password = "Li69nux*"
        self.management_interface_configured = True
        self.external_oam_interface_configured = True
        self.default_pxeboot_config()
        if not self.kubernetes:
            self.nameserver_addresses = ["", "", ""]

        if utils.is_cpe():
            self.system_mode = sysinv_constants.SYSTEM_MODE_DUPLEX

    def input_config(self):
        """Allow user to input configuration."""
        print("System Configuration")
        print("====================")
        print("Enter Q at any prompt to abort...\n")

        self.set_time()
        self.set_timezone(self)
        if utils.is_cpe():
            self.input_system_mode_config()
        self.check_storage_config()
        if self.system_mode == sysinv_constants.SYSTEM_MODE_SIMPLEX:
            self.default_pxeboot_config()
            self.input_aio_simplex_management_config()
        else:
            # An AIO system cannot function as a Distributed Cloud System
            # Controller
            if utils.get_system_type() != sysinv_constants.TIS_AIO_BUILD:
                self.input_dc_selection()
            self.input_pxeboot_config()
            self.input_management_config()
            if self.system_dc_role != \
                    sysinv_constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER \
                    and not self.kubernetes:
                # Disallow infrastructure network on systemcontroller,
                # as services located on infrastructure network will not
                # be reachable by subclouds.
                # Disallow infrastructure network on Kubernetes configs also.
                self.input_infrastructure_config()
        if self.kubernetes:
            self.input_cluster_host_config()
        self.input_external_oam_config()
        if self.kubernetes:
            self.input_dns_config()
            # Docker proxy is only used in kubernetes config
            self.input_docker_proxy_config()
            self.input_docker_registry_config()
        self.input_authentication_config()

    def is_valid_management_multicast_subnet(self, ip_subnet):
        """Determine whether the mgmt multicast subnet is valid."""
        # The multicast subnet must belong to the same Address Family
        # as the management network
        if ip_subnet.version != self.management_subnet.version:
            print(textwrap.fill(
                "Invalid network address - Management Multicast Subnet and "
                " Network IP Families must be the same.", 80))
            return False
        elif ip_subnet.size < 16:
            print("Subnet too small - must have at least 16 addresses")
            return False
        elif ip_subnet.ip != ip_subnet.network:
            print("Invalid network address")
            return False
        elif ip_subnet.version == 6 and ip_subnet.prefixlen < 64:
            print("IPv6 minimum prefix length is 64")
            return False
        elif not ip_subnet.is_multicast():
            print("Invalid network address - must be multicast")
            return False
        else:
            return True

    def input_config_from_file(self, configfile, restore=False):
        """Read configuration from answer or config file.

           WARNING: Any changes made here need to be reflected in the code
           that translates region config to this format in regionconfig.py.
        """
        if not os.path.isfile(configfile):
            print("Specified answer or config file not found")
            raise ConfigFail("Answer or Config file not found")

        config = configparser.RawConfigParser()
        config_sections = []

        try:
            config.read(configfile)
            config_sections = config.sections()

            self.system_mode = config.get('cSYSTEM', 'SYSTEM_MODE')
            if config.has_option('cSYSTEM', 'DISTRIBUTED_CLOUD_ROLE'):
                self.system_dc_role = \
                    config.get('cSYSTEM', 'DISTRIBUTED_CLOUD_ROLE')

            if config.has_option('cMETA', 'CONFIG_UUID'):
                self.config_uuid = config.get('cMETA', 'CONFIG_UUID')

            if config.has_option('cREGION', 'REGION_CONFIG'):
                self.region_config = config.getboolean(
                    'cREGION', 'REGION_CONFIG')

            if config.has_option('cREGION', 'REGION_SERVICES_CREATE'):
                self.region_services_create = config.getboolean(
                    'cREGION', 'REGION_SERVICES_CREATE')

            # Timezone configuration
            if config.has_option('cSYSTEM', 'TIMEZONE'):
                self.timezone = config.get('cSYSTEM', 'TIMEZONE')

            # Storage configuration
            if (config.has_option('cSTOR', 'DATABASE_STORAGE') or
                    config.has_option('cSTOR', 'IMAGE_STORAGE') or
                    config.has_option('cSTOR', 'BACKUP_STORAGE') or
                    config.has_option('cSTOR', 'IMAGE_CONVERSIONS_VOLUME') or
                    config.has_option('cSTOR', 'SHARED_INSTANCE_STORAGE') or
                    config.has_option('cSTOR', 'CINDER_BACKEND') or
                    config.has_option('cSTOR', 'CINDER_DEVICE') or
                    config.has_option('cSTOR', 'CINDER_LVM_TYPE') or
                    config.has_option('cSTOR', 'CINDER_STORAGE')):
                msg = "DATABASE_STORAGE, IMAGE_STORAGE, BACKUP_STORAGE, " + \
                    "IMAGE_CONVERSIONS_VOLUME, SHARED_INSTANCE_STORAGE, " + \
                    "CINDER_BACKEND, CINDER_DEVICE, CINDER_LVM_TYPE, " + \
                    "CINDER_STORAGE " + \
                    "are not valid entries in config file."
                raise ConfigFail(msg)

            # PXEBoot network configuration
            if config.has_option('cPXEBOOT', 'PXEBOOT_SUBNET'):
                self.separate_pxeboot_network = True
                self.pxeboot_subnet = IPNetwork(config.get(
                    'cPXEBOOT', 'PXEBOOT_SUBNET'))
                if config.has_option('cPXEBOOT', 'PXEBOOT_START_ADDRESS'):
                    self.pxeboot_start_address = IPAddress(config.get(
                        'cPXEBOOT', 'PXEBOOT_START_ADDRESS'))
                if config.has_option('cPXEBOOT', 'PXEBOOT_END_ADDRESS'):
                    self.pxeboot_end_address = IPAddress(config.get(
                        'cPXEBOOT', 'PXEBOOT_END_ADDRESS'))
                if not self.pxeboot_start_address and \
                        not self.pxeboot_end_address:
                    self.pxeboot_start_address = self.pxeboot_subnet[2]
                    self.pxeboot_end_address = self.pxeboot_subnet[-2]
                    self.use_entire_pxeboot_subnet = True
                else:
                    self.use_entire_pxeboot_subnet = False
                self.controller_pxeboot_address_0 = IPAddress(config.get(
                    'cPXEBOOT', 'CONTROLLER_PXEBOOT_ADDRESS_0'))
                self.controller_pxeboot_address_1 = IPAddress(config.get(
                    'cPXEBOOT', 'CONTROLLER_PXEBOOT_ADDRESS_1'))
                self.controller_pxeboot_floating_address = IPAddress(
                    config.get('cPXEBOOT',
                               'CONTROLLER_PXEBOOT_FLOATING_ADDRESS'))
            else:
                self.default_pxeboot_config()
            # Allow this to be optional for backwards compatibility
            if config.has_option('cPXEBOOT',
                                 'PXECONTROLLER_FLOATING_HOSTNAME'):
                self.pxecontroller_floating_hostname = config.get(
                    'cPXEBOOT', 'PXECONTROLLER_FLOATING_HOSTNAME')

            # Management network configuration
            if self.system_mode == sysinv_constants.SYSTEM_MODE_SIMPLEX and \
                    not self.subcloud_config():
                # For AIO-SX, only the management subnet is configurable
                # (unless this is a subcloud).
                if config.has_option('cMGMT', 'MANAGEMENT_SUBNET'):
                    management_subnet = IPNetwork(config.get(
                        'cMGMT', 'MANAGEMENT_SUBNET'))
                else:
                    management_subnet = IPNetwork(
                        constants.DEFAULT_MGMT_ON_LOOPBACK_SUBNET_IPV4)
                self.input_aio_simplex_management_config(
                    management_subnet=management_subnet)
            else:
                self.management_interface_name = config.get(
                    'cMGMT', 'MANAGEMENT_INTERFACE_NAME')
                self.management_interface = config.get(
                    'cMGMT', 'MANAGEMENT_INTERFACE')
                self.management_mtu = config.get(
                    'cMGMT', 'MANAGEMENT_MTU')
                self.management_subnet = IPNetwork(config.get(
                    'cMGMT', 'MANAGEMENT_SUBNET'))
                if config.has_option('cMGMT', 'MANAGEMENT_GATEWAY_ADDRESS'):
                    self.management_gateway_address = IPAddress(config.get(
                        'cMGMT', 'MANAGEMENT_GATEWAY_ADDRESS'))
                else:
                    self.management_gateway_address = None
                self.lag_management_interface = config.getboolean(
                    'cMGMT', 'LAG_MANAGEMENT_INTERFACE')
                if self.separate_pxeboot_network:
                    self.management_vlan = config.get('cMGMT',
                                                      'MANAGEMENT_VLAN')
                if self.lag_management_interface:
                    self.lag_management_interface_member0 = config.get(
                        'cMGMT', 'MANAGEMENT_BOND_MEMBER_0')
                    self.lag_management_interface_member1 = config.get(
                        'cMGMT', 'MANAGEMENT_BOND_MEMBER_1')
                    self.lag_management_interface_policy = config.get(
                        'cMGMT', 'MANAGEMENT_BOND_POLICY')
                self.controller_address_0 = IPAddress(config.get(
                    'cMGMT', 'CONTROLLER_0_ADDRESS'))
                self.controller_address_1 = IPAddress(config.get(
                    'cMGMT', 'CONTROLLER_1_ADDRESS'))
                self.controller_floating_address = IPAddress(config.get(
                    'cMGMT', 'CONTROLLER_FLOATING_ADDRESS'))
                if config.has_option('cMGMT', 'NFS_MANAGEMENT_ADDRESS_1'):
                    self.nfs_management_address_1 = IPAddress(config.get(
                        'cMGMT', 'NFS_MANAGEMENT_ADDRESS_1'))
                else:
                    self.nfs_management_address_1 = ''
                if config.has_option('cMGMT', 'NFS_MANAGEMENT_ADDRESS_2'):
                    self.nfs_management_address_2 = IPAddress(config.get(
                        'cMGMT', 'NFS_MANAGEMENT_ADDRESS_2'))
                else:
                    self.nfs_management_address_2 = ''
                self.controller_floating_hostname = config.get(
                    'cMGMT', 'CONTROLLER_FLOATING_HOSTNAME')
                self.controller_hostname_prefix = config.get(
                    'cMGMT', 'CONTROLLER_HOSTNAME_PREFIX')
                self.oamcontroller_floating_hostname = config.get(
                    'cMGMT', 'OAMCONTROLLER_FLOATING_HOSTNAME')

                if config.has_option('cMGMT', 'MANAGEMENT_MULTICAST_SUBNET'):
                    self.management_multicast_subnet = IPNetwork(config.get(
                        'cMGMT', 'MANAGEMENT_MULTICAST_SUBNET'))
                else:
                    if self.management_subnet.version == 6:
                        # Management subnet is IPv6, so set the default value
                        self.management_multicast_subnet = \
                            IPNetwork(constants.DEFAULT_MULTICAST_SUBNET_IPV6)
                    else:
                        self.management_multicast_subnet = \
                            IPNetwork(constants.DEFAULT_MULTICAST_SUBNET_IPV4)

                self.management_interface_configured = True
                if config.has_option('cMGMT', 'DYNAMIC_ADDRESS_ALLOCATION'):
                    self.dynamic_address_allocation = config.getboolean(
                        'cMGMT', 'DYNAMIC_ADDRESS_ALLOCATION')
                else:
                    self.dynamic_address_allocation = True
                if config.has_option('cMGMT', 'MANAGEMENT_START_ADDRESS'):
                    self.management_start_address = IPAddress(config.get(
                        'cMGMT', 'MANAGEMENT_START_ADDRESS'))
                if config.has_option('cMGMT', 'MANAGEMENT_END_ADDRESS'):
                    self.management_end_address = IPAddress(config.get(
                        'cMGMT', 'MANAGEMENT_END_ADDRESS'))
                if not self.management_start_address and \
                        not self.management_end_address:
                    self.management_start_address = self.management_subnet[2]
                    self.management_end_address = self.management_subnet[-2]
                    self.use_entire_mgmt_subnet = True

            # Infrastructure network configuration
            self.infrastructure_interface = ''
            if config.has_option('cINFRA', 'INFRASTRUCTURE_INTERFACE'):
                cvalue = config.get('cINFRA', 'INFRASTRUCTURE_INTERFACE')
                if cvalue != 'NC':
                    self.infrastructure_interface = cvalue
            if self.infrastructure_interface:
                self.infrastructure_mtu = config.get(
                    'cINFRA', 'INFRASTRUCTURE_MTU')
                self.infrastructure_vlan = ''
                if config.has_option('cINFRA',
                                     'INFRASTRUCTURE_INTERFACE_NAME'):
                    cvalue = config.get('cINFRA',
                                        'INFRASTRUCTURE_INTERFACE_NAME')
                    if cvalue != 'NC':
                        self.infrastructure_interface_name = cvalue
                if config.has_option('cINFRA', 'INFRASTRUCTURE_VLAN'):
                    cvalue = config.get('cINFRA', 'INFRASTRUCTURE_VLAN')
                    if cvalue != 'NC':
                        self.infrastructure_vlan = cvalue
                self.lag_infrastructure_interface = config.getboolean(
                    'cINFRA', 'LAG_INFRASTRUCTURE_INTERFACE')
                if self.lag_infrastructure_interface:
                    self.lag_infrastructure_interface_member0 = config.get(
                        'cINFRA', 'INFRASTRUCTURE_BOND_MEMBER_0')
                    self.lag_infrastructure_interface_member1 = config.get(
                        'cINFRA', 'INFRASTRUCTURE_BOND_MEMBER_1')
                    self.lag_infrastructure_interface_policy = config.get(
                        'cINFRA', 'INFRASTRUCTURE_BOND_POLICY')
                self.infrastructure_subnet = IPNetwork(config.get(
                    'cINFRA', 'INFRASTRUCTURE_SUBNET'))
                self.controller_infrastructure_address_0 = IPAddress(
                    config.get('cINFRA',
                               'CONTROLLER_0_INFRASTRUCTURE_ADDRESS'))
                self.controller_infrastructure_address_1 = IPAddress(
                    config.get('cINFRA',
                               'CONTROLLER_1_INFRASTRUCTURE_ADDRESS'))
                if config.has_option('cINFRA', 'NFS_INFRASTRUCTURE_ADDRESS_1'):
                    self.nfs_infrastructure_address_1 = IPAddress(config.get(
                        'cINFRA', 'NFS_INFRASTRUCTURE_ADDRESS_1'))
                self.infrastructure_interface_configured = True
                if config.has_option('cINFRA', 'INFRASTRUCTURE_START_ADDRESS'):
                    self.infrastructure_start_address = IPAddress(
                        config.get('cINFRA',
                                   'INFRASTRUCTURE_START_ADDRESS'))
                if config.has_option('cINFRA', 'INFRASTRUCTURE_END_ADDRESS'):
                    self.infrastructure_end_address = IPAddress(
                        config.get('cINFRA',
                                   'INFRASTRUCTURE_END_ADDRESS'))
                if not self.infrastructure_start_address and \
                        not self.infrastructure_end_address:
                    self.use_entire_infra_subnet = True

            # Cluster network configuration
            if self.kubernetes:
                if config.has_section('cCLUSTER'):
                    self.cluster_host_interface_name = config.get(
                        'cCLUSTER', 'CLUSTER_INTERFACE_NAME')
                    self.cluster_host_interface = config.get(
                        'cCLUSTER', 'CLUSTER_INTERFACE')
                    self.cluster_host_mtu = config.get(
                        'cCLUSTER', 'CLUSTER_MTU')
                    self.cluster_host_vlan = ''
                    if config.has_option('cCLUSTER', 'CLUSTER_VLAN'):
                        cvalue = config.get('cCLUSTER', 'CLUSTER_VLAN')
                        if cvalue != 'NC':
                            self.cluster_host_vlan = cvalue
                    self.lag_cluster_host_interface = config.getboolean(
                        'cCLUSTER', 'LAG_CLUSTER_INTERFACE')
                    if self.lag_cluster_host_interface:
                        self.lag_cluster_host_interface_member0 = config.get(
                            'cCLUSTER', 'CLUSTER_BOND_MEMBER_0')
                        self.lag_cluster_host_interface_member1 = config.get(
                            'cCLUSTER', 'CLUSTER_BOND_MEMBER_1')
                        self.lag_cluster_host_interface_policy = config.get(
                            'cCLUSTER', 'CLUSTER_BOND_POLICY')
                    self.cluster_host_subnet = IPNetwork(config.get(
                        'cCLUSTER', 'CLUSTER_SUBNET'))
                else:
                    self.cluster_host_interface_name = \
                        self.management_interface_name
                    self.cluster_host_interface = self.management_interface
                    self.cluster_host_vlan = self.management_vlan
                self.cluster_host_interface_configured = True

            # External OAM network configuration
            self.external_oam_interface_name = config.get(
                'cEXT_OAM', 'EXTERNAL_OAM_INTERFACE_NAME')
            self.external_oam_interface = config.get(
                'cEXT_OAM', 'EXTERNAL_OAM_INTERFACE')
            self.external_oam_mtu = config.get(
                'cEXT_OAM', 'EXTERNAL_OAM_MTU')
            self.external_oam_vlan = ''
            if config.has_option('cEXT_OAM', 'EXTERNAL_OAM_VLAN'):
                cvalue = config.get('cEXT_OAM', 'EXTERNAL_OAM_VLAN')
                if cvalue != 'NC':
                    self.external_oam_vlan = cvalue
            self.external_oam_subnet = IPNetwork(config.get(
                'cEXT_OAM', 'EXTERNAL_OAM_SUBNET'))
            self.lag_external_oam_interface = config.getboolean(
                'cEXT_OAM', 'LAG_EXTERNAL_OAM_INTERFACE')
            if self.lag_external_oam_interface:
                self.lag_external_oam_interface_member0 = config.get(
                    'cEXT_OAM', 'EXTERNAL_OAM_BOND_MEMBER_0')
                self.lag_external_oam_interface_member1 = config.get(
                    'cEXT_OAM', 'EXTERNAL_OAM_BOND_MEMBER_1')
                self.lag_external_oam_interface_policy = config.get(
                    'cEXT_OAM', 'EXTERNAL_OAM_BOND_POLICY')
            else:
                self.lag_external_oam_interface_member0 = None
                self.lag_external_oam_interface_member1 = None
                self.lag_external_oam_interface_policy = None
                self.lag_external_oam_interface_txhash = None

            if config.has_option('cEXT_OAM', 'EXTERNAL_OAM_GATEWAY_ADDRESS'):
                self.external_oam_gateway_address = IPAddress(config.get(
                    'cEXT_OAM', 'EXTERNAL_OAM_GATEWAY_ADDRESS'))
            else:
                self.external_oam_gateway_address = None
            self.external_oam_floating_address = IPAddress(config.get(
                'cEXT_OAM', 'EXTERNAL_OAM_FLOATING_ADDRESS'))
            self.external_oam_address_0 = IPAddress(config.get(
                'cEXT_OAM', 'EXTERNAL_OAM_0_ADDRESS'))
            self.external_oam_address_1 = IPAddress(config.get(
                'cEXT_OAM', 'EXTERNAL_OAM_1_ADDRESS'))

            self.external_oam_interface_configured = True

            # DNS configuration
            if self.kubernetes:
                if config.has_section('cDNS'):
                    self.nameserver_addresses = ["", "", ""]
                    for x in range(0, len(self.nameserver_addresses)):
                        if config.has_option('cDNS',
                                             'NAMESERVER_' + str(x + 1)):
                            cvalue = config.get('cDNS',
                                                'NAMESERVER_' + str(x + 1))
                            if cvalue != "NC" and cvalue != "":
                                self.nameserver_addresses[x] = \
                                    IPAddress(cvalue)

                # Docker Proxy Configuration
                if config.has_section('cDOCKER_PROXY'):
                    self.enable_docker_proxy = True
                    if config.has_option('cDOCKER_PROXY',
                                         'DOCKER_HTTP_PROXY'):
                        self.docker_http_proxy = config.get(
                            'cDOCKER_PROXY', 'DOCKER_HTTP_PROXY')
                    if config.has_option('cDOCKER_PROXY',
                                         'DOCKER_HTTPS_PROXY'):
                        self.docker_https_proxy = config.get(
                            'cDOCKER_PROXY', 'DOCKER_HTTPS_PROXY')
                    if config.has_option('cDOCKER_PROXY',
                                         'DOCKER_NO_PROXY'):
                        self.docker_no_proxy = config.get(
                            'cDOCKER_PROXY', 'DOCKER_NO_PROXY')

                # Docker Registry Configuration
                if config.has_section('cDOCKER_REGISTRY'):
                    self.docker_use_default_registry = False
                    if config.has_option('cDOCKER_REGISTRY',
                                         'DOCKER_K8S_REGISTRY'):
                        self.docker_k8s_registry = config.get(
                            'cDOCKER_REGISTRY', 'DOCKER_K8S_REGISTRY')
                    if config.has_option('cDOCKER_REGISTRY',
                                         'DOCKER_GCR_REGISTRY'):
                        self.docker_gcr_registry = config.get(
                            'cDOCKER_REGISTRY', 'DOCKER_GCR_REGISTRY')
                    if config.has_option('cDOCKER_REGISTRY',
                                         'DOCKER_QUAY_REGISTRY'):
                        self.docker_quay_registry = config.get(
                            'cDOCKER_REGISTRY', 'DOCKER_QUAY_REGISTRY')
                    if config.has_option('cDOCKER_REGISTRY',
                                         'DOCKER_DOCKER_REGISTRY'):
                        self.docker_docker_registry = config.get(
                            'cDOCKER_REGISTRY', 'DOCKER_DOCKER_REGISTRY')
                    if config.has_option('cDOCKER_REGISTRY',
                                         'IS_SECURE_REGISTRY'):
                        self.is_secure_registry = config.getboolean(
                            'cDOCKER_REGISTRY', 'IS_SECURE_REGISTRY')
                    else:
                        self.is_secure_registry = True

            # SDN Network configuration
            if config.has_option('cSDN', 'ENABLE_SDN'):
                raise ConfigFail("The option ENABLE_SDN is no longer "
                                 "supported.")

            # Authentication configuration
            if config.has_section('cAUTHENTICATION'):
                if config.has_option('cAUTHENTICATION', 'ADMIN_PASSWORD'):
                    self.admin_password = config.get(
                        'cAUTHENTICATION', 'ADMIN_PASSWORD')

            if self.admin_password == "" and not restore:
                print("Admin password must be set in answer file")
                raise ConfigFail("Admin password not set in answer file")
            # the admin password will be validated
            self.add_password_for_validation('ADMIN_PASSWORD',
                                             self.admin_password)

            if config.has_option('cUSERS', 'WRSROOT_SIG'):
                raise ConfigFail("The option WRSROOT_SIG is "
                                 "no longer supported.")

            # Licensing configuration
            if config.has_option('cLICENSING', 'LICENSE_FILE'):
                raise ConfigFail("The option LICENSE_FILE is "
                                 "no longer supported")

            # Security configuration
            if config.has_option('cSECURITY', 'CONFIG_WRSROOT_PW_AGE'):
                raise ConfigFail("The option CONFIG_WRSROOT_PW_AGE is "
                                 "no longer supported.")
            if config.has_option('cSECURITY', 'ENABLE_HTTPS'):
                raise ConfigFail("The option ENABLE_HTTPS is  "
                                 "no longer supported.")
            if config.has_option('cSECURITY', 'FIREWALL_RULES_FILE'):
                raise ConfigFail("The option FIREWALL_RULES_FILE is "
                                 "no longer supported")

            # Region configuration
            if self.region_config:
                self.region_1_name = config.get(
                    'cREGION', 'REGION_1_NAME')
                self.region_2_name = config.get(
                    'cREGION', 'REGION_2_NAME')
                self.admin_username = config.get(
                    'cREGION', 'ADMIN_USER_NAME')
                if config.has_option('cREGION', 'ADMIN_USER_DOMAIN'):
                    self.admin_user_domain = config.get(
                        'cREGION', 'ADMIN_USER_DOMAIN')
                if config.has_option('cREGION', 'ADMIN_PROJECT_NAME'):
                    self.admin_project_name = config.get(
                        'cREGION', 'ADMIN_PROJECT_NAME')
                else:
                    self.admin_project_name = config.get(
                        'cREGION', 'ADMIN_TENANT_NAME')
                if config.has_option('cREGION', 'ADMIN_PROJECT_DOMAIN'):
                    self.admin_project_domain = config.get(
                        'cREGION', 'ADMIN_PROJECT_DOMAIN')
                if config.has_option('cREGION', 'SERVICE_PROJECT_NAME'):
                    self.service_project_name = config.get(
                        'cREGION', 'SERVICE_PROJECT_NAME')
                else:
                    self.service_project_name = config.get(
                        'cREGION', 'SERVICE_TENANT_NAME')
                if config.has_option('cREGION', 'USER_DOMAIN_NAME'):
                    self.service_user_domain = config.get(
                        'cREGION', 'USER_DOMAIN_NAME')
                if config.has_option('cREGION', 'PROJECT_DOMAIN_NAME'):
                    self.service_project_domain = config.get(
                        'cREGION', 'PROJECT_DOMAIN_NAME')
                self.keystone_auth_uri = config.get(
                    'cREGION', 'KEYSTONE_AUTH_URI')
                self.keystone_identity_uri = config.get(
                    'cREGION', 'KEYSTONE_IDENTITY_URI')
                self.keystone_admin_uri = config.get(
                    'cREGION', 'KEYSTONE_ADMIN_URI')
                self.keystone_internal_uri = config.get(
                    'cREGION', 'KEYSTONE_INTERNAL_URI')
                self.keystone_public_uri = config.get(
                    'cREGION', 'KEYSTONE_PUBLIC_URI')
                self.keystone_service_name = config.get(
                    'cREGION', 'KEYSTONE_SERVICE_NAME')
                self.keystone_service_type = config.get(
                    'cREGION', 'KEYSTONE_SERVICE_TYPE')
                if config.has_option('cREGION', 'LDAP_REGION_NAME'):
                    self.ldap_region_name = config.get(
                        'cREGION', 'LDAP_REGION_NAME')
                if config.has_option('cREGION', 'LDAP_SERVICE_NAME'):
                    self.ldap_service_name = config.get(
                        'cREGION', 'LDAP_SERVICE_NAME')
                if config.has_option('cREGION', 'LDAP_SERVICE_URI'):
                    self.ldap_service_uri = config.get(
                        'cREGION', 'LDAP_SERVICE_URI')
                self.patching_ks_user_name = config.get(
                    'cREGION', 'PATCHING_USER_NAME')
                self.patching_ks_password = config.get(
                    'cREGION', 'PATCHING_PASSWORD')
                self.add_password_for_validation('PATCHING_PASSWORD',
                                                 self.patching_ks_password)
                self.sysinv_ks_user_name = config.get(
                    'cREGION', 'SYSINV_USER_NAME')
                self.sysinv_ks_password = config.get(
                    'cREGION', 'SYSINV_PASSWORD')
                self.add_password_for_validation('SYSINV_PASSWORD',
                                                 self.sysinv_ks_password)
                self.sysinv_service_name = config.get(
                    'cREGION', 'SYSINV_SERVICE_NAME')
                self.sysinv_service_type = config.get(
                    'cREGION', 'SYSINV_SERVICE_TYPE')
                self.mtce_ks_user_name = config.get(
                    'cREGION', 'MTCE_USER_NAME')
                self.mtce_ks_password = config.get(
                    'cREGION', 'MTCE_PASSWORD')
                self.add_password_for_validation('MTCE_PASSWORD',
                                                 self.mtce_ks_password)

                self.nfv_ks_user_name = config.get(
                    'cREGION', 'NFV_USER_NAME')
                self.nfv_ks_password = config.get(
                    'cREGION', 'NFV_PASSWORD')
                self.add_password_for_validation('NFV_PASSWORD',
                                                 self.nfv_ks_password)
                self.fm_ks_user_name = config.get(
                    'cREGION', 'FM_USER_NAME')
                self.fm_ks_password = config.get(
                    'cREGION', 'FM_PASSWORD')
                self.add_password_for_validation('FM_PASSWORD',
                                                 self.fm_ks_password)

                self.barbican_ks_user_name = config.get(
                    'cREGION', 'BARBICAN_USER_NAME')
                self.barbican_ks_password = config.get(
                    'cREGION', 'BARBICAN_PASSWORD')
                self.add_password_for_validation('BARBICAN_PASSWORD',
                                                 self.barbican_ks_password)

                self.shared_services.append(self.keystone_service_type)

                if self.subcloud_config():
                    self.system_controller_subnet = IPNetwork(config.get(
                        'cREGION', 'SYSTEM_CONTROLLER_SUBNET'))
                    self.system_controller_floating_ip = config.get(
                        'cREGION', 'SYSTEM_CONTROLLER_FLOATING_ADDRESS')

            # Deprecated Ceilometer time_to_live option.
            # made this a ceilometer service parameter.
            if config.has_option('cCEILOMETER', 'TIME_TO_LIVE'):
                raise ConfigFail("The option TIME_TO_LIVE is "
                                 "no longer supported")

        except Exception:
            print("Error parsing answer file")
            raise

        return config_sections

    def display_config(self):
        """Display configuration that will be applied."""
        print("\nThe following configuration will be applied:")

        print("\nSystem Configuration")
        print("--------------------")
        print("Time Zone: " + str(self.timezone))
        print("System mode: %s" % self.system_mode)
        if self.system_type != sysinv_constants.TIS_AIO_BUILD:
            dc_role_true = "no"
            if (self.system_dc_role ==
                    sysinv_constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER):
                dc_role_true = "yes"
            print("Distributed Cloud System Controller: %s" % dc_role_true)

        print("\nPXEBoot Network Configuration")
        print("-----------------------------")
        if not self.separate_pxeboot_network:
            print("Separate PXEBoot network not configured")
        else:
            print("PXEBoot subnet: " + str(self.pxeboot_subnet.cidr))
            print("PXEBoot floating address: " +
                  str(self.controller_pxeboot_floating_address))
            print("Controller 0 PXEBoot address: " +
                  str(self.controller_pxeboot_address_0))
            print("Controller 1 PXEBoot address: " +
                  str(self.controller_pxeboot_address_1))
            if not self.use_entire_pxeboot_subnet:
                print("PXEBoot start address: " +
                      str(self.pxeboot_start_address))
                print("PXEBoot end address: " + str(self.pxeboot_end_address))
        print("PXEBoot Controller floating hostname: " +
              str(self.pxecontroller_floating_hostname))

        print("\nManagement Network Configuration")
        print("--------------------------------")
        print("Management interface name: " + self.management_interface_name)
        print("Management interface: " + self.management_interface)
        if self.management_vlan:
            print("Management vlan: " + self.management_vlan)
        print("Management interface MTU: " + self.management_mtu)
        if self.lag_management_interface:
            print("Management ae member 0: " +
                  self.lag_management_interface_member0)
            print("Management ae member 1: " +
                  self.lag_management_interface_member1)
            print("Management ae policy : " +
                  self.lag_management_interface_policy)
        print("Management subnet: " + str(self.management_subnet.cidr))
        if self.management_gateway_address:
            print("Management gateway address: " +
                  str(self.management_gateway_address))
        print("Controller floating address: " +
              str(self.controller_floating_address))
        print("Controller 0 address: " + str(self.controller_address_0))
        print("Controller 1 address: " + str(self.controller_address_1))
        print("NFS Management Address 1: " +
              str(self.nfs_management_address_1))
        if not self.infrastructure_interface:
            print("NFS Management Address 2: " +
                  str(self.nfs_management_address_2))
        print("Controller floating hostname: " +
              str(self.controller_floating_hostname))
        print("Controller hostname prefix: " + self.controller_hostname_prefix)
        print("OAM Controller floating hostname: " +
              str(self.oamcontroller_floating_hostname))
        if not self.use_entire_mgmt_subnet:
            print("Management start address: " +
                  str(self.management_start_address))
            print("Management end address: " +
                  str(self.management_end_address))
        if self.dynamic_address_allocation:
            print("Dynamic IP address allocation is selected")
        print("Management multicast subnet: " +
              str(self.management_multicast_subnet))

        print("\nInfrastructure Network Configuration")
        print("------------------------------------")
        if not self.infrastructure_interface:
            print("Infrastructure interface not configured")
        else:
            print("Infrastructure interface name: " +
                  self.infrastructure_interface_name)
            print("Infrastructure interface: " + self.infrastructure_interface)
            if self.infrastructure_vlan:
                print("Infrastructure vlan: " + self.infrastructure_vlan)
            print("Infrastructure interface MTU: " + self.infrastructure_mtu)
            if self.lag_infrastructure_interface:
                print("Infrastructure ae member 0: " +
                      self.lag_infrastructure_interface_member0)
                print("Infrastructure ae member 1: " +
                      self.lag_infrastructure_interface_member1)
                print("Infrastructure ae policy : " +
                      self.lag_infrastructure_interface_policy)
            print("Infrastructure subnet: " +
                  str(self.infrastructure_subnet.cidr))
            print("Controller 0 infrastructure address: " +
                  str(self.controller_infrastructure_address_0))
            print("Controller 1 infrastructure address: " +
                  str(self.controller_infrastructure_address_1))
            print("NFS Infrastructure Address 1: " +
                  str(self.nfs_infrastructure_address_1))
            print("Controller infrastructure hostname suffix: " +
                  self.controller_infrastructure_hostname_suffix)
            if not self.use_entire_infra_subnet:
                print("Infrastructure start address: " +
                      str(self.infrastructure_start_address))
                print("Infrastructure end address: " +
                      str(self.infrastructure_end_address))

        if self.kubernetes:
            print("\nKubernetes Cluster Network Configuration")
            print("----------------------------------------")
            print("Cluster pod network subnet: " +
                  str(self.cluster_pod_subnet.cidr))
            print("Cluster service network subnet: " +
                  str(self.cluster_service_subnet.cidr))
            print("Cluster host interface name: " +
                  self.cluster_host_interface_name)
            print("Cluster host interface: " + self.cluster_host_interface)
            if self.infrastructure_vlan:
                print("Cluster host vlan: " + self.cluster_host_vlan)
            print("Cluster host interface MTU: " + self.cluster_host_mtu)
            if self.lag_cluster_host_interface:
                print("Cluster host ae member 0: " +
                      self.lag_cluster_host_interface_member0)
                print("Cluster host ae member 1: " +
                      self.lag_cluster_host_interface_member1)
                print("Cluster host ae policy : " +
                      self.lag_cluster_host_interface_policy)
            print("Cluster host subnet: " +
                  str(self.cluster_host_subnet.cidr))

        print("\nExternal OAM Network Configuration")
        print("----------------------------------")
        print("External OAM interface name: " +
              self.external_oam_interface_name)
        print("External OAM interface: " + self.external_oam_interface)
        if self.external_oam_vlan:
            print("External OAM vlan: " + self.external_oam_vlan)
        print("External OAM interface MTU: " + self.external_oam_mtu)
        if self.lag_external_oam_interface:
            print("External OAM ae member 0: " +
                  self.lag_external_oam_interface_member0)
            print("External OAM ae member 1: " +
                  self.lag_external_oam_interface_member1)
            print("External OAM ae policy : " +
                  self.lag_external_oam_interface_policy)
        print("External OAM subnet: " + str(self.external_oam_subnet))
        if self.external_oam_gateway_address:
            print("External OAM gateway address: " +
                  str(self.external_oam_gateway_address))
        if self.system_mode != sysinv_constants.SYSTEM_MODE_SIMPLEX:
            print("External OAM floating address: " +
                  str(self.external_oam_floating_address))
            print("External OAM 0 address: " +
                  str(self.external_oam_address_0))
            print("External OAM 1 address: " +
                  str(self.external_oam_address_1))
        else:
            print("External OAM address: " + str(self.external_oam_address_0))

        if self.kubernetes:
            print("\nDNS Configuration")
            print("-----------------")
            dns_config = False
            for x in range(0, len(self.nameserver_addresses)):
                if self.nameserver_addresses[x]:
                    print("Nameserver " + str(x + 1) + ": " +
                          str(self.nameserver_addresses[x]))
                    dns_config = True
            if not dns_config:
                print("External DNS servers not configured")
            if self.enable_docker_proxy:
                print("\nDocker Proxy Configuration")
                print("--------------------------")
                if self.docker_http_proxy:
                    print("Docker HTTP proxy: " + self.docker_http_proxy)
                if self.docker_https_proxy:
                    print("Docker HTTPS proxy: " + self.docker_https_proxy)
                if self.docker_no_proxy:
                    print("Docker NO proxy: " + self.docker_no_proxy)
            if not self.docker_use_default_registry:
                print("\nDocker Registry Configuration")
                print("-----------------------------")
                if self.docker_k8s_registry:
                    print("Alternative registry to k8s.gcr.io: " +
                          self.docker_k8s_registry)
                if self.docker_gcr_registry:
                    print("Alternative registry to gcr.io: " +
                          self.docker_gcr_registry)
                if self.docker_quay_registry:
                    print("Alternative registry to quay.io: " +
                          self.docker_quay_registry)
                if self.docker_docker_registry:
                    print("Alternative registry to docker.io: " +
                          self.docker_docker_registry)
                print("Is registries secure: " +
                      str(self.is_secure_registry))

        if self.region_config:
            print("\nRegion Configuration")
            print("--------------------")
            print("Region 1 name: " + self.region_1_name)
            print("Region 2 name: " + self.region_2_name)
            print("Admin user name: " + self.admin_username)
            print("Admin user domain: " + self.admin_user_domain)
            print("Admin project name: " + self.admin_project_name)
            print("Admin project domain: " + self.admin_project_domain)
            print("Service project name: " + self.service_project_name)
            print("Service user domain: " + self.service_user_domain)
            print("Service project domain: " + self.service_project_domain)
            print("Keystone auth URI: " + self.keystone_auth_uri)
            print("Keystone identity URI: " + self.keystone_identity_uri)
            print("Keystone admin URI: " + self.keystone_admin_uri)
            print("Keystone internal URI: " + self.keystone_internal_uri)
            print("Keystone public URI: " + self.keystone_public_uri)
            print("Keystone service name: " + self.keystone_service_name)
            print("Keystone service type: " + self.keystone_service_type)
            print("LDAP service name: " + self.ldap_service_name)
            print("LDAP region: " + self.ldap_region_name)
            print("LDAP service URI:" + self.ldap_service_uri)
            print("Patching user name: " + self.patching_ks_user_name)
            print("Sysinv user name: " + self.sysinv_ks_user_name)
            print("Sysinv service name: " + self.sysinv_service_name)
            print("Sysinv service type: " + self.sysinv_service_type)

        if self.subcloud_config():
            print("\nSubcloud Configuration")
            print("----------------------")
            print("System controller subnet: " +
                  str(self.system_controller_subnet.cidr))
            print("System controller floating ip: " +
                  str(self.system_controller_floating_ip))

    def write_config_file(self):
        """Write configuration to a text file for later reference."""
        try:
            os.makedirs(constants.CONFIG_WORKDIR, stat.S_IRWXU | stat.S_IRGRP |
                        stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        except OSError as exc:
            if exc.errno == errno.EEXIST and os.path.isdir(
                    constants.CONFIG_WORKDIR):
                pass
            else:
                LOG.error("Failed to create config directory: %s",
                          constants.CONFIG_WORKDIR)
                raise ConfigFail("Failed to write configuration file")

        try:
            with open(constants.CGCS_CONFIG_FILE, 'w') as f:
                # System configuration
                f.write("[cSYSTEM]\n")
                f.write("# System Configuration\n")
                f.write("SYSTEM_MODE=" + str(self.system_mode) + "\n")
                if self.system_dc_role is not None:
                    f.write("DISTRIBUTED_CLOUD_ROLE=" +
                            str(self.system_dc_role) + "\n")
                # Time Zone configuration
                f.write("TIMEZONE=" + str(self.timezone) + "\n")

                # PXEBoot network configuration
                f.write("\n[cPXEBOOT]")
                f.write("\n# PXEBoot Network Support Configuration\n")
                if self.separate_pxeboot_network:
                    f.write("PXEBOOT_SUBNET=" +
                            str(self.pxeboot_subnet.cidr) + "\n")
                    f.write("CONTROLLER_PXEBOOT_FLOATING_ADDRESS=" +
                            str(self.controller_pxeboot_floating_address) +
                            "\n")
                    f.write("CONTROLLER_PXEBOOT_ADDRESS_0=" +
                            str(self.controller_pxeboot_address_0) + "\n")
                    f.write("CONTROLLER_PXEBOOT_ADDRESS_1=" +
                            str(self.controller_pxeboot_address_1) + "\n")
                f.write("PXECONTROLLER_FLOATING_HOSTNAME=" +
                        str(self.pxecontroller_floating_hostname) + "\n")

                # Management network configuration
                f.write("\n[cMGMT]")
                f.write("\n# Management Network Configuration\n")
                f.write("MANAGEMENT_INTERFACE_NAME=" +
                        self.management_interface_name + "\n")
                f.write("MANAGEMENT_INTERFACE=" + self.management_interface +
                        "\n")
                if self.separate_pxeboot_network:
                    f.write("MANAGEMENT_VLAN=" + self.management_vlan + "\n")
                f.write("MANAGEMENT_MTU=" + self.management_mtu + "\n")
                f.write("MANAGEMENT_SUBNET=" +
                        str(self.management_subnet.cidr) + "\n")
                if self.management_gateway_address:
                    f.write("MANAGEMENT_GATEWAY_ADDRESS=" +
                            str(self.management_gateway_address) + "\n")
                if self.lag_management_interface:
                    f.write("LAG_MANAGEMENT_INTERFACE=yes\n")
                    f.write("MANAGEMENT_BOND_MEMBER_0=" +
                            str(self.lag_management_interface_member0) + "\n")
                    f.write("MANAGEMENT_BOND_MEMBER_1=" +
                            str(self.lag_management_interface_member1) + "\n")
                    f.write("MANAGEMENT_BOND_POLICY=" +
                            str(self.lag_management_interface_policy) + "\n")
                else:
                    f.write("LAG_MANAGEMENT_INTERFACE=no\n")
                f.write("CONTROLLER_FLOATING_ADDRESS=" +
                        str(self.controller_floating_address) + "\n")
                f.write("CONTROLLER_0_ADDRESS=" +
                        str(self.controller_address_0) + "\n")
                f.write("CONTROLLER_1_ADDRESS=" +
                        str(self.controller_address_1) + "\n")
                f.write("NFS_MANAGEMENT_ADDRESS_1=" +
                        str(self.nfs_management_address_1) + "\n")
                if not self.infrastructure_interface:
                    f.write("NFS_MANAGEMENT_ADDRESS_2=" +
                            str(self.nfs_management_address_2) + "\n")
                f.write("CONTROLLER_FLOATING_HOSTNAME=" +
                        str(self.controller_floating_hostname) + "\n")
                f.write("CONTROLLER_HOSTNAME_PREFIX=" +
                        self.controller_hostname_prefix + "\n")
                f.write("OAMCONTROLLER_FLOATING_HOSTNAME=" +
                        str(self.oamcontroller_floating_hostname) + "\n")
                if self.dynamic_address_allocation:
                    f.write("DYNAMIC_ADDRESS_ALLOCATION=yes\n")
                else:
                    f.write("DYNAMIC_ADDRESS_ALLOCATION=no\n")
                if self.region_config or not self.use_entire_mgmt_subnet:
                    f.write("MANAGEMENT_START_ADDRESS=" +
                            str(self.management_start_address) + "\n")
                    f.write("MANAGEMENT_END_ADDRESS=" +
                            str(self.management_end_address) + "\n")
                f.write("MANAGEMENT_MULTICAST_SUBNET=" +
                        str(self.management_multicast_subnet) + "\n")

                # Infrastructure network configuration
                f.write("\n[cINFRA]")
                f.write("\n# Infrastructure Network Configuration\n")
                if self.infrastructure_interface:
                    f.write("INFRASTRUCTURE_INTERFACE_NAME="
                            + self.infrastructure_interface_name + "\n")
                    f.write("INFRASTRUCTURE_INTERFACE="
                            + self.infrastructure_interface + "\n")
                    f.write("INFRASTRUCTURE_VLAN="
                            + self.infrastructure_vlan + "\n")
                    f.write("INFRASTRUCTURE_MTU="
                            + self.infrastructure_mtu + "\n")
                    f.write("INFRASTRUCTURE_SUBNET=" +
                            str(self.infrastructure_subnet.cidr) + "\n")
                    if self.lag_infrastructure_interface:
                        f.write("LAG_INFRASTRUCTURE_INTERFACE=yes\n")
                        f.write("INFRASTRUCTURE_BOND_MEMBER_0=" +
                                str(self.lag_infrastructure_interface_member0)
                                + "\n")
                        f.write("INFRASTRUCTURE_BOND_MEMBER_1=" +
                                str(self.lag_infrastructure_interface_member1)
                                + "\n")
                        f.write("INFRASTRUCTURE_BOND_POLICY=" +
                                str(self.lag_infrastructure_interface_policy)
                                + "\n")
                    else:
                        f.write("LAG_INFRASTRUCTURE_INTERFACE=no\n")
                    f.write("CONTROLLER_0_INFRASTRUCTURE_ADDRESS=" +
                            str(self.controller_infrastructure_address_0)
                            + "\n")
                    f.write("CONTROLLER_1_INFRASTRUCTURE_ADDRESS=" +
                            str(self.controller_infrastructure_address_1)
                            + "\n")
                    f.write("NFS_INFRASTRUCTURE_ADDRESS_1=" +
                            str(self.nfs_infrastructure_address_1) + "\n")
                    f.write("CONTROLLER_INFRASTRUCTURE_HOSTNAME_SUFFIX=" +
                            self.controller_infrastructure_hostname_suffix
                            + "\n")
                    f.write("INFRASTRUCTURE_START_ADDRESS=" +
                            str(self.infrastructure_start_address) + "\n")
                    f.write("INFRASTRUCTURE_END_ADDRESS=" +
                            str(self.infrastructure_end_address) + "\n")
                else:
                    f.write("INFRASTRUCTURE_INTERFACE_NAME=NC\n")
                    f.write("INFRASTRUCTURE_INTERFACE=NC\n")
                    f.write("INFRASTRUCTURE_VLAN=NC\n")
                    f.write("INFRASTRUCTURE_MTU=NC\n")
                    f.write("INFRASTRUCTURE_SUBNET=NC\n")
                    f.write("LAG_INFRASTRUCTURE_INTERFACE=no\n")
                    f.write("INFRASTRUCTURE_BOND_MEMBER_0=NC\n")
                    f.write("INFRASTRUCTURE_BOND_MEMBER_1=NC\n")
                    f.write("INFRASTRUCTURE_BOND_POLICY=NC\n")
                    f.write("CONTROLLER_0_INFRASTRUCTURE_ADDRESS=NC\n")
                    f.write("CONTROLLER_1_INFRASTRUCTURE_ADDRESS=NC\n")
                    f.write("NFS_INFRASTRUCTURE_ADDRESS_1=NC\n")
                    f.write("STORAGE_0_INFRASTRUCTURE_ADDRESS=NC\n")
                    f.write("STORAGE_1_INFRASTRUCTURE_ADDRESS=NC\n")
                    f.write("CONTROLLER_INFRASTRUCTURE_HOSTNAME_SUFFIX=NC\n")
                    f.write("INFRASTRUCTURE_START_ADDRESS=NC\n")
                    f.write("INFRASTRUCTURE_END_ADDRESS=NC\n")

                # Cluster host network configuration
                if self.kubernetes:
                    f.write("\n[cCLUSTER]")
                    f.write("\n# Cluster Host Network Configuration\n")
                    f.write("CLUSTER_INTERFACE_NAME="
                            + self.cluster_host_interface_name + "\n")
                    f.write("CLUSTER_INTERFACE="
                            + self.cluster_host_interface + "\n")
                    if self.cluster_host_vlan:
                        f.write("CLUSTER_VLAN="
                                + self.cluster_host_vlan + "\n")
                    else:
                        f.write("CLUSTER_VLAN=NC\n")
                    f.write("CLUSTER_MTU="
                            + self.cluster_host_mtu + "\n")
                    f.write("CLUSTER_SUBNET=" +
                            str(self.cluster_host_subnet.cidr) + "\n")
                    if self.lag_cluster_host_interface:
                        f.write("LAG_CLUSTER_INTERFACE=yes\n")
                        f.write("CLUSTER_BOND_MEMBER_0=" +
                                str(self.lag_cluster_host_interface_member0)
                                + "\n")
                        f.write("CLUSTER_BOND_MEMBER_1=" +
                                str(self.lag_cluster_host_interface_member1)
                                + "\n")
                        f.write("CLUSTER_BOND_POLICY=" +
                                str(self.lag_cluster_host_interface_policy)
                                + "\n")
                    else:
                        f.write("LAG_CLUSTER_INTERFACE=no\n")

                # External OAM network configuration
                f.write("\n[cEXT_OAM]")
                f.write("\n# External OAM Network Configuration\n")
                f.write("EXTERNAL_OAM_INTERFACE_NAME=" +
                        self.external_oam_interface_name + "\n")
                f.write("EXTERNAL_OAM_INTERFACE=" +
                        self.external_oam_interface + "\n")
                if self.external_oam_vlan:
                    f.write("EXTERNAL_OAM_VLAN="
                            + self.external_oam_vlan + "\n")
                else:
                    f.write("EXTERNAL_OAM_VLAN=NC\n")
                f.write("EXTERNAL_OAM_MTU=" +
                        self.external_oam_mtu + "\n")
                if self.lag_external_oam_interface:
                    f.write("LAG_EXTERNAL_OAM_INTERFACE=yes\n")
                    f.write("EXTERNAL_OAM_BOND_MEMBER_0=" +
                            str(self.lag_external_oam_interface_member0) +
                            "\n")
                    f.write("EXTERNAL_OAM_BOND_MEMBER_1=" +
                            str(self.lag_external_oam_interface_member1) +
                            "\n")
                    f.write("EXTERNAL_OAM_BOND_POLICY=" +
                            str(self.lag_external_oam_interface_policy) +
                            "\n")
                else:
                    f.write("LAG_EXTERNAL_OAM_INTERFACE=no\n")
                f.write("EXTERNAL_OAM_SUBNET=" +
                        str(self.external_oam_subnet) + "\n")
                if self.external_oam_gateway_address:
                    f.write("EXTERNAL_OAM_GATEWAY_ADDRESS=" +
                            str(self.external_oam_gateway_address) + "\n")
                f.write("EXTERNAL_OAM_FLOATING_ADDRESS=" +
                        str(self.external_oam_floating_address) + "\n")
                f.write("EXTERNAL_OAM_0_ADDRESS=" +
                        str(self.external_oam_address_0) + "\n")
                f.write("EXTERNAL_OAM_1_ADDRESS=" +
                        str(self.external_oam_address_1) + "\n")

                if self.kubernetes:
                    # DNS configuration
                    f.write("\n[cDNS]")
                    f.write("\n# DNS Configuration\n")
                    for x in range(0, len(self.nameserver_addresses)):
                        if self.nameserver_addresses[x]:
                            f.write("NAMESERVER_" + str(x + 1) + "=" +
                                    str(self.nameserver_addresses[x]) + "\n")
                        else:
                            f.write("NAMESERVER_" + str(x + 1) + "=NC" + "\n")

                    # Docker proxy configuration
                    if self.enable_docker_proxy:
                        f.write("\n[cDOCKER_PROXY]")
                        f.write("\n# Docker Proxy Configuration\n")
                        if self.docker_http_proxy:
                            f.write(
                                "DOCKER_HTTP_PROXY=" +
                                str(self.docker_http_proxy) + "\n")
                        if self.docker_https_proxy:
                            f.write(
                                "DOCKER_HTTPS_PROXY=" +
                                str(self.docker_https_proxy) + "\n")
                        if self.docker_no_proxy:
                            f.write(
                                "DOCKER_NO_PROXY=" +
                                str(self.docker_no_proxy) + "\n")

                    # Docker registry configuration
                    if not self.docker_use_default_registry:
                        f.write("\n[cDOCKER_REGISTRY]")
                        f.write("\n# Docker Registry Configuration\n")
                        if self.docker_k8s_registry:
                            f.write(
                                "DOCKER_K8S_REGISTRY=" +
                                str(self.docker_k8s_registry) + "\n")
                        if self.docker_gcr_registry:
                            f.write(
                                "DOCKER_GCR_REGISTRY=" +
                                str(self.docker_gcr_registry) + "\n")
                        if self.docker_quay_registry:
                            f.write(
                                "DOCKER_QUAY_REGISTRY=" +
                                str(self.docker_quay_registry) + "\n")
                        if self.docker_docker_registry:
                            f.write(
                                "DOCKER_DOCKER_REGISTRY=" +
                                str(self.docker_docker_registry) + "\n")
                        f.write(
                            "IS_SECURE_REGISTRY=" +
                            str(self.is_secure_registry) + "\n")

                # Security configuration
                f.write("\n[cSECURITY]")

                # Region configuration
                f.write("\n[cREGION]")
                f.write("\n# Region Configuration\n")
                f.write("REGION_CONFIG=" + str(self.region_config) + "\n")
                if self.region_config:
                    f.write("REGION_1_NAME=%s\n" %
                            self.region_1_name)
                    f.write("REGION_2_NAME=%s\n" %
                            self.region_2_name)
                    f.write("ADMIN_USER_NAME=%s\n" %
                            self.admin_username)
                    f.write("ADMIN_USER_DOMAIN=%s\n" %
                            self.admin_user_domain)
                    f.write("ADMIN_PROJECT_NAME=%s\n" %
                            self.admin_project_name)
                    f.write("ADMIN_PROJECT_DOMAIN=%s\n" %
                            self.admin_project_domain)
                    f.write("SERVICE_PROJECT_NAME=%s\n" %
                            self.service_project_name)
                    f.write("SERVICE_USER_DOMAIN=%s\n" %
                            self.service_user_domain)
                    f.write("SERVICE_PROJECT_DOMAIN=%s\n" %
                            self.service_project_domain)
                    f.write("KEYSTONE_AUTH_URI=%s\n" %
                            self.keystone_auth_uri)
                    f.write("KEYSTONE_IDENTITY_URI=%s\n" %
                            self.keystone_identity_uri)
                    f.write("KEYSTONE_ADMIN_URI=%s\n" %
                            self.keystone_admin_uri)
                    f.write("KEYSTONE_INTERNAL_URI=%s\n" %
                            self.keystone_internal_uri)
                    f.write("KEYSTONE_PUBLIC_URI=%s\n" %
                            self.keystone_public_uri)
                    f.write("KEYSTONE_SERVICE_NAME=%s\n" %
                            self.keystone_service_name)
                    f.write("KEYSTONE_SERVICE_TYPE=%s\n" %
                            self.keystone_service_type)
                    if self.ldap_service_name:
                        f.write("LDAP_SERVICE_NAME=%s\n" %
                                self.ldap_service_name)
                    if self.ldap_region_name:
                        f.write("LDAP_REGION_NAME=%s\n" %
                                self.ldap_region_name)
                    if self.ldap_service_uri:
                        f.write("LDAP_SERVICE_URI=%s\n" %
                                self.ldap_service_uri)
                    f.write("PATCHING_USER_NAME=%s\n" %
                            self.patching_ks_user_name)
                    f.write("PATCHING_PASSWORD=%s\n" %
                            self.patching_ks_password)
                    f.write("SYSINV_USER_NAME=%s\n" %
                            self.sysinv_ks_user_name)
                    f.write("SYSINV_PASSWORD=%s\n" %
                            self.sysinv_ks_password)
                    f.write("SYSINV_SERVICE_NAME=%s\n" %
                            self.sysinv_service_name)
                    f.write("SYSINV_SERVICE_TYPE=%s\n" %
                            self.sysinv_service_type)
                    f.write("NFV_USER_NAME=%s\n" %
                            self.nfv_ks_user_name)
                    f.write("NFV_PASSWORD=%s\n" %
                            self.nfv_ks_password)
                    f.write("MTCE_USER_NAME=%s\n" %
                            self.mtce_ks_user_name)
                    f.write("MTCE_PASSWORD=%s\n" %
                            self.mtce_ks_password)
                    f.write("FM_USER_NAME=%s\n" %
                            self.fm_ks_user_name)
                    f.write("FM_PASSWORD=%s\n" %
                            self.fm_ks_password)
                    f.write("BARBICAN_USER_NAME=%s\n" %
                            self.barbican_ks_user_name)
                    f.write("BARBICAN_PASSWORD=%s\n" %
                            self.barbican_ks_password)

                # Subcloud configuration
                if self.subcloud_config():
                    f.write("SUBCLOUD_CONFIG=%s\n" %
                            str(self.subcloud_config()))
                    f.write("SYSTEM_CONTROLLER_SUBNET=%s\n" %
                            str(self.system_controller_subnet))
                    f.write("SYSTEM_CONTROLLER_FLOATING_ADDRESS=%s\n" %
                            str(self.system_controller_floating_ip))

        except IOError:
            LOG.error("Failed to open file: %s", constants.CGCS_CONFIG_FILE)
            raise ConfigFail("Failed to write configuration file")

    def setup_pxeboot_files(self):
        """Create links for default pxeboot configuration files"""
        try:
            if self.dynamic_address_allocation:
                default_pxelinux = "/pxeboot/pxelinux.cfg.files/default"
                efi_grub_cfg = "/pxeboot/pxelinux.cfg.files/grub.cfg"
            else:
                default_pxelinux = "/pxeboot/pxelinux.cfg.files/default.static"
                efi_grub_cfg = "/pxeboot/pxelinux.cfg.files/grub.cfg.static"
            subprocess.check_call(["ln", "-s",
                                   default_pxelinux,
                                   "/pxeboot/pxelinux.cfg/default"])
            subprocess.check_call(["ln", "-s",
                                   efi_grub_cfg,
                                   "/pxeboot/pxelinux.cfg/grub.cfg"])
        except subprocess.CalledProcessError:
            LOG.error("Failed to create pxelinux.cfg/default or "
                      "grub.cfg symlink")
            raise ConfigFail("Failed to persist config files")

    def verify_branding(self):
        """ Verify the constraints for custom branding procedure """
        found = False
        for f in os.listdir('/opt/branding'):
            if f in ['applied', 'horizon-region-exclusions.csv']:
                continue
            if not f.endswith('.tgz'):
                raise ConfigFail('/opt/branding/%s is not a valid branding '
                                 'file name, refer '
                                 'to the branding readme in the SDK' % f)
            else:
                if found:
                    raise ConfigFail(
                        'Only one branding tarball is permitted in /opt/'
                        'branding, refer to the branding readme in the SDK')
                found = True

    def persist_local_config(self):
        utils.persist_config()

        if os.path.isdir('/opt/banner'):
            utils.apply_banner_customization()

    def finalize_controller_config(self):

        # restart maintenance to pick up configuration changes
        utils.mtce_restart()

        self.setup_pxeboot_files()

        # pass control over to service management (SM)
        utils.mark_config_complete()

    def wait_service_enable(self):
        # wait for the following service groups to go active
        services = [
            'oam-services',
            'controller-services',
            'cloud-services',
            'patching-services',
            'directory-services',
            'web-services',
            'vim-services',
        ]

        if self.system_dc_role == \
                sysinv_constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
            services.append('distributed-cloud-services')

        count = len(services)
        egrep = '"^(%s)[[:space:]]*active[[:space:]]*active"' % \
                '|'.join(services)
        cmd = 'test $(sm-dump | grep -E %s | wc -l) -eq %d' % (egrep, count)

        interval = 10
        for _ in range(0, constants.SERVICE_ENABLE_TIMEOUT, interval):
            try:
                subprocess.check_call(cmd, shell=True,
                                      stderr=subprocess.STDOUT)
                return
            except subprocess.CalledProcessError:
                pass
            time.sleep(interval)
        else:
            raise ConfigFail('Timeout waiting for service enable')

    def store_admin_password(self):
        """Store the supplied admin password in the temporary keyring vault"""
        os.environ["XDG_DATA_HOME"] = "/tmp"
        keyring.set_password("CGCS", self.admin_username, self.admin_password)
        del os.environ["XDG_DATA_HOME"]

    def create_bootstrap_config(self):
        self.store_admin_password()
        if self.region_config:
            self._store_service_password()
        utils.create_static_config()

    def apply_bootstrap_manifest(self):
        filename = None
        try:
            utils.apply_manifest(self.controller_address_0,
                                 sysinv_constants.CONTROLLER,
                                 'bootstrap',
                                 constants.HIERADATA_WORKDIR,
                                 runtime_filename=filename)
        except Exception as e:
            LOG.exception(e)
            raise ConfigFail(
                'Failed to apply bootstrap manifest. '
                'See /var/log/puppet/latest/puppet.log for details.')

    def apply_controller_manifest(self):
        try:
            utils.apply_manifest(self.controller_address_0,
                                 sysinv_constants.CONTROLLER,
                                 'controller',
                                 constants.HIERADATA_PERMDIR)
        except Exception as e:
            LOG.exception(e)
            raise ConfigFail(
                'Failed to apply controller manifest. '
                'See /var/log/puppet/latest/puppet.log for details.')

    def add_password_for_validation(self, key, password):
        """Add the config key and the password to be validated """
        if key and password:
            for idx, stanza in enumerate(self.openstack_passwords):
                if key in stanza:
                    # this password was previously added for validation,
                    # simply update the password value
                    self.openstack_passwords[idx][key] = password
                    return
            self.openstack_passwords.append({key: password})

    def process_validation_passwords(self, console=False):
        """Validate the list of openstack passwords """
        if (self.os_password_rules_file and
                not os.path.exists(self.os_password_rules_file)):
            msg = ("Password rules file could not be found(%s) "
                   "Password rules cannot be applied" %
                   self.os_password_rules_file)
            LOG.error(msg)
            raise ConfigFail("Failed to apply Openstack password rules")

        if len(self.openstack_passwords) == 0:
            # nothing to validate
            return True
        for stanza in self.openstack_passwords:
            try:
                ret, msg = validate_openstack_password(
                    stanza.values()[0], self.os_password_rules_file)
                if not ret:
                    # one of the openstack passwords failed validation!
                    fail_msg = ("%s: %s" % (stanza.keys()[0], msg))
                    if console:
                        print(textwrap.fill(fail_msg, 80))
                        return False
                    raise ConfigFail(fail_msg)
            except Exception as e:
                # this implies an internal issue, either with
                # the parsing rules or the validator. In the
                # interest of robustness, we will proceed without
                # password rules and possibly provision them
                # later using service parameters
                LOG.error("Failure on validating openstack password: %s" % e)
                raise ConfigFail("%s" % e)
        return True

    def _wait_system_config(self, client):
        for _ in range(constants.SYSTEM_CONFIG_TIMEOUT):
            try:
                systems = client.sysinv.isystem.list()
                if systems:
                    # only one system (default)
                    return systems[0]
            except Exception:
                pass
            time.sleep(1)
        else:
            raise ConfigFail('Timeout waiting for default system '
                             'configuration')

    def _wait_ethernet_port_config(self, client, host):
        count = 0
        for _ in range(constants.SYSTEM_CONFIG_TIMEOUT / 10):
            try:
                ports = client.sysinv.ethernet_port.list(host.uuid)
                if ports and count == len(ports):
                    return ports
                count = len(ports)
            except Exception:
                pass
            time.sleep(10)
        else:
            raise ConfigFail('Timeout waiting for controller port '
                             'configuration')

    def _wait_disk_config(self, client, host):
        count = 0
        for _ in range(constants.SYSTEM_CONFIG_TIMEOUT / 10):
            try:
                disks = client.sysinv.idisk.list(host.uuid)
                if disks and count == len(disks):
                    return disks
                count = len(disks)
            except Exception:
                pass
            if disks:
                time.sleep(1)  # We don't need to wait that long
            else:
                time.sleep(10)
        else:
            raise ConfigFail('Timeout waiting for controller disk '
                             'configuration')

    def _wait_pv_config(self, client, host):
        count = 0
        for _ in range(constants.SYSTEM_CONFIG_TIMEOUT / 10):
            try:
                pvs = client.sysinv.ipv.list(host.uuid)
                if pvs and count == len(pvs):
                    return pvs
                count = len(pvs)
            except Exception:
                pass
            if pvs:
                time.sleep(1)  # We don't need to wait that long
            else:
                time.sleep(10)
        else:
            raise ConfigFail('Timeout waiting for controller PV '
                             'configuration')

    def _populate_system_config(self, client):
        # Wait for pre-populated system
        system = self._wait_system_config(client)

        # Update system attributes
        capabilities = {'region_config': self.region_config,
                        'vswitch_type': str(self.vswitch_type),
                        'shared_services': str(self.shared_services),
                        'sdn_enabled': self.enable_sdn,
                        'https_enabled': self.enable_https,
                        'kubernetes_enabled': self.kubernetes}

        system_type = utils.get_system_type()

        region_name = constants.DEFAULT_REGION_NAME
        if self.region_config:
            region_name = self.region_2_name

        values = {
            'system_type': system_type,
            'system_mode': str(self.system_mode),
            'capabilities': capabilities,
            'timezone': str(self.timezone),
            'region_name': region_name,
            'service_project_name': self.service_project_name
        }
        if self.system_dc_role in \
                [sysinv_constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER,
                 sysinv_constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD]:
            values['distributed_cloud_role'] = self.system_dc_role
            if self.system_dc_role == \
                    sysinv_constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
                # Set the system name to the subcloud name for subclouds
                values['name'] = region_name

        patch = sysinv.dict_to_patch(values)
        client.sysinv.isystem.update(system.uuid, patch)

        if self.region_config:
            self._populate_region_config(client)

    def _populate_region_config(self, client):
        self._populate_service_config(client)

    def _populate_service_config(self, client):
        # populate service attributes in services table

        # Strip the version from the URIs
        modified_identity_uri = (re.split(r'/v[0-9]',
                                 self.keystone_identity_uri)[0])
        modified_auth_uri = (re.split(r'/v[0-9]',
                             self.keystone_auth_uri)[0])
        modified_admin_uri = (re.split(r'/v[0-9]',
                              self.keystone_admin_uri)[0])
        modified_internal_uri = (re.split(r'/v[0-9]',
                                 self.keystone_internal_uri)[0])
        modified_public_uri = (re.split(r'/v[0-9]',
                               self.keystone_public_uri)[0])

        # always populates keystone config
        capabilities = {'admin_user_domain': self.admin_user_domain,
                        'admin_project_domain': self.admin_project_domain,
                        'service_user_domain': self.service_user_domain,
                        'service_project_domain': self.service_project_domain,
                        'admin_user_name': self.admin_username,
                        'admin_project_name': self.admin_project_name,
                        'auth_uri': modified_auth_uri,
                        'auth_url': modified_identity_uri,
                        'service_name': self.keystone_service_name,
                        'service_type': self.keystone_service_type,
                        'region_services_create': self.region_services_create}

        # TODO (aning): Once we eliminate duplicated endpoints of shared
        # services for non-primary region(s), we can remove the following code
        # that pass over the URLs to sysinv for puppet to create these
        # endpoints.
        if modified_admin_uri:
            capabilities.update({'admin_uri': modified_admin_uri})
        if modified_internal_uri:
            capabilities.update({'internal_uri': modified_internal_uri})
        if modified_public_uri:
            capabilities.update({'public_uri': modified_public_uri})

        values = {'name': 'keystone',
                  'enabled': True,
                  'region_name': self.region_1_name,
                  'capabilities': capabilities}
        client.sysinv.sm_service.service_create(**values)

        # fm service config
        capabilities = {'user_name': self.fm_ks_user_name}
        values = {'name': "fm",
                  'enabled': True,
                  'region_name': self.region_2_name,
                  'capabilities': capabilities}
        client.sysinv.sm_service.service_create(**values)

        # if ldap is a shared service
        if self.ldap_service_uri:
            capabilities = {'service_name': self.ldap_service_name}
            capabilities.update({'service_uri': self.ldap_service_uri})
            values = {'name': self.ldap_service_name,
                      'enabled': True,
                      'region_name': self.ldap_region_name,
                      'capabilities': capabilities}
            client.sysinv.sm_service.service_create(**values)

        # sysinv service config
        capabilities = {'service_name': self.sysinv_service_name,
                        'service_type': self.sysinv_service_type,
                        'user_name': self.sysinv_ks_user_name}
        values = {'name': self.sysinv_service_name,
                  'enabled': True,
                  'region_name': self.region_2_name,
                  'capabilities': capabilities}
        client.sysinv.sm_service.service_create(**values)

        # populate patching service config
        capabilities = {'service_name': 'patching',
                        'service_type': 'patching',
                        'user_name': self.patching_ks_user_name}
        values = {'name': 'patching',
                  'enabled': True,
                  'region_name': self.region_2_name,
                  'capabilities': capabilities}
        client.sysinv.sm_service.service_create(**values)

        # mtc service config
        capabilities = {'user_name': self.mtce_ks_user_name}
        values = {'name': "mtce",
                  'enabled': True,
                  'region_name': self.region_2_name,
                  'capabilities': capabilities}
        client.sysinv.sm_service.service_create(**values)

        # nfv service config
        capabilities = {'user_name': self.nfv_ks_user_name}
        values = {'name': "vim",
                  'enabled': True,
                  'region_name': self.region_2_name,
                  'capabilities': capabilities}
        client.sysinv.sm_service.service_create(**values)

        # barbican service config
        capabilities = {'user_name': self.barbican_ks_user_name}
        values = {'name': "barbican",
                  'enabled': True,
                  'region_name': self.region_2_name,
                  'capabilities': capabilities}
        client.sysinv.sm_service.service_create(**values)

    def _store_service_password(self):
        # store service password in the temporary keyring vault

        os.environ["XDG_DATA_HOME"] = "/tmp"

        keyring.set_password(self.sysinv_service_name,
                             constants.DEFAULT_SERVICE_PROJECT_NAME,
                             self.sysinv_ks_password)

        keyring.set_password('patching',
                             constants.DEFAULT_SERVICE_PROJECT_NAME,
                             self.patching_ks_password)

        keyring.set_password('mtce', constants.DEFAULT_SERVICE_PROJECT_NAME,
                             self.mtce_ks_password)

        keyring.set_password('vim', constants.DEFAULT_SERVICE_PROJECT_NAME,
                             self.nfv_ks_password)

        keyring.set_password('fm', constants.DEFAULT_SERVICE_PROJECT_NAME,
                             self.fm_ks_password)

        keyring.set_password('barbican',
                             constants.DEFAULT_SERVICE_PROJECT_NAME,
                             self.barbican_ks_password)

        del os.environ["XDG_DATA_HOME"]

    def _populate_network_config(self, client):
        self._populate_mgmt_network(client)
        self._populate_pxeboot_network(client)
        self._populate_infra_network(client)
        self._populate_oam_network(client)
        self._populate_multicast_network(client)
        if self.kubernetes:
            self._populate_cluster_host_network(client)
            self._populate_cluster_pod_network(client)
            self._populate_cluster_service_network(client)
        if self.subcloud_config():
            self._populate_system_controller_network(client)

    def _populate_mgmt_network(self, client):
        # create the address pool
        values = {
            'name': 'management',
            'network': str(self.management_subnet.network),
            'prefix': self.management_subnet.prefixlen,
            'ranges': [(str(self.management_start_address),
                        str(self.management_end_address))],
        }
        if self.management_gateway_address:
            values.update({
                'gateway_address': str(self.management_gateway_address)})
        pool = client.sysinv.address_pool.create(**values)

        # create the network for the pool
        values = {
            'type': sysinv_constants.NETWORK_TYPE_MGMT,
            'name': sysinv_constants.NETWORK_TYPE_MGMT,
            'dynamic': self.dynamic_address_allocation,
            'pool_uuid': pool.uuid,
        }

        client.sysinv.network.create(**values)

    def _populate_pxeboot_network(self, client):
        # create the address pool
        values = {
            'name': 'pxeboot',
            'network': str(self.pxeboot_subnet.network),
            'prefix': self.pxeboot_subnet.prefixlen,
            'ranges': [(str(self.pxeboot_start_address),
                       str(self.pxeboot_end_address))],
        }
        pool = client.sysinv.address_pool.create(**values)

        # create the network for the pool
        values = {
            'type': sysinv_constants.NETWORK_TYPE_PXEBOOT,
            'name': sysinv_constants.NETWORK_TYPE_PXEBOOT,
            'dynamic': True,
            'pool_uuid': pool.uuid,
        }
        client.sysinv.network.create(**values)

    def _populate_infra_network(self, client):
        if not self.infrastructure_interface:
            return  # infrastructure network not configured

        # create the address pool
        values = {
            'name': 'infrastructure',
            'network': str(self.infrastructure_subnet.network),
            'prefix': self.infrastructure_subnet.prefixlen,
            'ranges': [(str(self.infrastructure_start_address),
                        str(self.infrastructure_end_address))],
        }
        pool = client.sysinv.address_pool.create(**values)

        # create the network for the pool
        values = {
            'type': sysinv_constants.NETWORK_TYPE_INFRA,
            'name': sysinv_constants.NETWORK_TYPE_INFRA,
            'dynamic': self.dynamic_address_allocation,
            'pool_uuid': pool.uuid,
        }

        client.sysinv.network.create(**values)

    def _populate_oam_network(self, client):

        # set default range if not specified as part of configuration
        self.external_oam_start_address = self.external_oam_subnet[1]
        self.external_oam_end_address = self.external_oam_subnet[-2]

        # create the address pool
        values = {
            'name': 'oam',
            'network': str(self.external_oam_subnet.network),
            'prefix': self.external_oam_subnet.prefixlen,
            'ranges': [(str(self.external_oam_start_address),
                        str(self.external_oam_end_address))],
            'floating_address': str(self.external_oam_floating_address),
        }

        if self.system_mode != sysinv_constants.SYSTEM_MODE_SIMPLEX:
            values.update({
                'controller0_address': str(self.external_oam_address_0),
                'controller1_address': str(self.external_oam_address_1),
            })
        if self.external_oam_gateway_address:
            values.update({
                'gateway_address': str(self.external_oam_gateway_address),
            })
        pool = client.sysinv.address_pool.create(**values)

        # create the network for the pool
        values = {
            'type': sysinv_constants.NETWORK_TYPE_OAM,
            'name': sysinv_constants.NETWORK_TYPE_OAM,
            'dynamic': False,
            'pool_uuid': pool.uuid,
        }

        client.sysinv.network.create(**values)

    def _populate_multicast_network(self, client):
        # create the address pool
        values = {
            'name': 'multicast-subnet',
            'network': str(self.management_multicast_subnet.network),
            'prefix': self.management_multicast_subnet.prefixlen,
            'ranges': [(str(self.management_multicast_subnet[1]),
                        str(self.management_multicast_subnet[-2]))],
        }
        pool = client.sysinv.address_pool.create(**values)

        # create the network for the pool
        values = {
            'type': sysinv_constants.NETWORK_TYPE_MULTICAST,
            'name': sysinv_constants.NETWORK_TYPE_MULTICAST,
            'dynamic': False,
            'pool_uuid': pool.uuid,
        }
        client.sysinv.network.create(**values)

    def _populate_system_controller_network(self, client):
        # create the address pool
        values = {
            'name': 'system-controller-subnet',
            'network': str(self.system_controller_subnet.network),
            'prefix': self.system_controller_subnet.prefixlen,
            'floating_address': str(self.system_controller_floating_ip),
        }
        pool = client.sysinv.address_pool.create(**values)

        # create the network for the pool
        values = {
            'type': sysinv_constants.NETWORK_TYPE_SYSTEM_CONTROLLER,
            'name': sysinv_constants.NETWORK_TYPE_SYSTEM_CONTROLLER,
            'dynamic': False,
            'pool_uuid': pool.uuid,
        }
        client.sysinv.network.create(**values)

    def _populate_cluster_host_network(self, client):

        # set default range if not specified as part of configuration
        self.cluster_host_subnet_start_address = self.cluster_host_subnet[2]
        self.cluster_host_subnet_end_address = self.cluster_host_subnet[-2]

        # create the address pool
        values = {
            'name': 'cluster-host-subnet',
            'network': str(self.cluster_host_subnet.network),
            'prefix': self.cluster_host_subnet.prefixlen,
            'ranges': [(str(self.cluster_host_subnet_start_address),
                        str(self.cluster_host_subnet_end_address))],
        }
        pool = client.sysinv.address_pool.create(**values)

        # create the network for the pool
        values = {
            'type': sysinv_constants.NETWORK_TYPE_CLUSTER_HOST,
            'name': sysinv_constants.NETWORK_TYPE_CLUSTER_HOST,
            'dynamic': self.dynamic_address_allocation,
            'pool_uuid': pool.uuid,
        }
        client.sysinv.network.create(**values)

    def _populate_cluster_pod_network(self, client):
        # create the address pool
        values = {
            'name': 'cluster-pod-subnet',
            'network': str(self.cluster_pod_subnet.network),
            'prefix': self.cluster_pod_subnet.prefixlen,
            'ranges': [(str(self.cluster_pod_subnet[1]),
                        str(self.cluster_pod_subnet[-2]))],
        }
        pool = client.sysinv.address_pool.create(**values)

        # create the network for the pool
        values = {
            'type': sysinv_constants.NETWORK_TYPE_CLUSTER_POD,
            'name': sysinv_constants.NETWORK_TYPE_CLUSTER_POD,
            'dynamic': False,
            'pool_uuid': pool.uuid,
        }
        client.sysinv.network.create(**values)

    def _populate_cluster_service_network(self, client):
        # create the address pool
        values = {
            'name': 'cluster-service-subnet',
            'network': str(self.cluster_service_subnet.network),
            'prefix': self.cluster_service_subnet.prefixlen,
            'ranges': [(str(self.cluster_service_subnet[1]),
                        str(self.cluster_service_subnet[-2]))],
        }
        pool = client.sysinv.address_pool.create(**values)

        # create the network for the pool
        values = {
            'type': sysinv_constants.NETWORK_TYPE_CLUSTER_SERVICE,
            'name': sysinv_constants.NETWORK_TYPE_CLUSTER_SERVICE,
            'dynamic': False,
            'pool_uuid': pool.uuid,
        }
        client.sysinv.network.create(**values)

    def _populate_network_addresses(self, client, pool, network, addresses):
        for name, address in addresses.items():
            values = {
                'pool_uuid': pool.uuid,
                'address': str(address),
                'prefix': pool.prefix,
                'name': "%s-%s" % (name, network.type),
            }
            client.sysinv.address.create(**values)

    def _inventory_config_complete_wait(self, client, controller):

        # This is a gate for the generation of hiera data.

        # TODO: Really need this to detect when inventory is
        # TODO: .. complete at the host level rather than each
        # TODO: .. individual entity being populated as it is
        # TODO: .. today for storage.

        # Wait for sysinv-agent to populate disks and PVs
        self._wait_disk_config(client, controller)
        self._wait_pv_config(client, controller)

    def _get_management_mac_address(self):

        if self.lag_management_interface:
            ifname = self.lag_management_interface_member0
        else:
            ifname = self.management_interface

        try:
            filename = '/sys/class/net/%s/address' % ifname
            with open(filename, 'r') as f:
                return f.readline().rstrip()
        except Exception:
            raise ConfigFail("Failed to obtain mac address of %s" % ifname)

    def _populate_controller_config(self, client):
        mgmt_mac = self._get_management_mac_address()
        rootfs_device = get_device_from_function(get_rootfs_node)
        boot_device = get_device_from_function(find_boot_device)
        console = get_console_info()
        tboot = get_tboot_info()
        install_output = get_orig_install_mode()

        provision_state = sysinv.HOST_PROVISIONED
        if utils.is_combined_load():
            provision_state = sysinv.HOST_PROVISIONING

        values = {
            'personality': sysinv.HOST_PERSONALITY_CONTROLLER,
            'hostname': self.controller_hostname_prefix + "0",
            'mgmt_ip': str(self.controller_address_0),
            'mgmt_mac': mgmt_mac,
            'administrative': sysinv.HOST_ADMIN_STATE_LOCKED,
            'operational': sysinv.HOST_OPERATIONAL_STATE_DISABLED,
            'availability': sysinv.HOST_AVAIL_STATE_OFFLINE,
            'invprovision': provision_state,
            'rootfs_device': rootfs_device,
            'boot_device': boot_device,
            'console': console,
            'tboot': tboot,
            'install_output': install_output,
        }
        controller = client.sysinv.ihost.create(**values)
        return controller

    def _populate_interface_config(self, client, controller):
        # Wait for Ethernet port inventory
        self._wait_ethernet_port_config(client, controller)

        self._populate_management_interface(client, controller)
        self._populate_infrastructure_interface(client, controller)
        self._populate_oam_interface(client, controller)
        if self.kubernetes:
            self._populate_cluster_host_interface(client, controller)

    def _update_interface_config(self, client, values):
        host_uuid = values.get('ihost_uuid')
        ifname = values.get('ifname')
        interfaces = client.sysinv.iinterface.list(host_uuid)
        for interface in interfaces:
            if interface.ifname == ifname:
                patch = sysinv.dict_to_patch(values)
                client.sysinv.iinterface.update(interface.uuid, patch)
                break
        else:
            raise ConfigFail("Failed to find interface %s" % ifname)

    def _get_interface(self, client, host_uuid, ifname):
        interfaces = client.sysinv.iinterface.list(host_uuid)
        for interface in interfaces:
            if interface.ifname == ifname:
                return interface
        else:
            raise ConfigFail("Failed to find interface %s" % ifname)

    def _get_interface_aemode(self, aemode):
        """Convert the AE mode to an AE mode supported by the interface API"""
        if aemode == constants.LAG_MODE_ACTIVE_BACKUP:
            return 'active_standby'
        elif aemode == constants.LAG_MODE_BALANCE_XOR:
            return 'balanced'
        elif aemode == constants.LAG_MODE_8023AD:
            return '802.3ad'
        else:
            raise ConfigFail("Unknown interface AE mode: %s" % aemode)

    def _get_interface_txhashpolicy(self, aemode):
        """Convert the AE mode to a L2 hash supported by the interface API"""
        if aemode == constants.LAG_MODE_ACTIVE_BACKUP:
            return None
        elif aemode == constants.LAG_MODE_BALANCE_XOR:
            return constants.LAG_TXHASH_LAYER2
        elif aemode == constants.LAG_MODE_8023AD:
            return constants.LAG_TXHASH_LAYER2
        else:
            raise ConfigFail("Unknown interface AE mode: %s" % aemode)

    def _get_network(self, client, network_type):
        networks = client.sysinv.network.list()
        for net in networks:
            if net.type == network_type:
                return net
        else:
            raise ConfigFail("Failed to find network %s" % type)

    def _get_interface_mtu(self, ifname):
        """
        This function determines the MTU value that must be configured on an
        interface.  It is accounting for the possibility that different network
        types are sharing the same interfaces in which case the lowest
        interface must have an interface equal to or greater than any of the
        VLAN interfaces above it.  The input semantic checks enforce specific
        precedence rules (e.g., infra must be less than or equal to the mgmt
        mtu if infra is a vlan over mgmt), but this function allows for any
        permutation to avoid issues if the semantic checks are loosened or if
        the ini input method allows different possibities.

        This function must not be used for VLAN interfaces.  VLAN interfaces
        have no requirement to be large enough to accomodate another VLAN above
        it so for those interfaces we simply use the interface MTU as was
        specified by the user.
        """
        value = 0
        if self.management_interface_configured:
            if ifname == self.management_interface:
                value = max(value, self.management_mtu)
        if self.infrastructure_interface_configured:
            if ifname == self.infrastructure_interface:
                value = max(value, self.infrastructure_mtu)
        if self.cluster_host_interface_configured:
            if ifname == self.cluster_host_interface:
                value = max(value, self.cluster_host_mtu)
        if self.external_oam_interface_configured:
            if ifname == self.external_oam_interface:
                value = max(value, self.external_oam_mtu)
        assert value != 0
        return value

    def _populate_management_interface(self, client, controller):
        """Configure the management/pxeboot interface(s)"""

        interface_class = sysinv_constants.INTERFACE_CLASS_PLATFORM
        if self.management_vlan:
            network = self._get_network(client,
                                        sysinv_constants.NETWORK_TYPE_PXEBOOT)
        else:
            network = self._get_network(client,
                                        sysinv_constants.NETWORK_TYPE_MGMT)

        if self.lag_management_interface:
            members = [self.lag_management_interface_member0]
            if self.lag_management_interface_member1:
                members.append(self.lag_management_interface_member1)

            aemode = self._get_interface_aemode(
                self.lag_management_interface_policy)

            txhashpolicy = self._get_interface_txhashpolicy(
                self.lag_management_interface_policy)

            values = {
                'ihost_uuid': controller.uuid,
                'ifname': self.management_interface,
                'imtu': self.management_mtu,
                'iftype': 'ae',
                'aemode': aemode,
                'txhashpolicy': txhashpolicy,
                'ifclass': interface_class,
                'networks': [str(network.id)],
                'uses': members,
            }

            client.sysinv.iinterface.create(**values)
        elif self.system_mode == sysinv_constants.SYSTEM_MODE_SIMPLEX and \
                not self.subcloud_config():
            # Create the management interface record for the loopback interface
            values = {
                'ihost_uuid': controller.uuid,
                'ifname': self.management_interface,
                'imtu': self.management_mtu,
                'iftype': sysinv_constants.INTERFACE_TYPE_VIRTUAL,
                'ifclass': interface_class,
                'networks': [str(network.id)],
            }
            client.sysinv.iinterface.create(**values)
        else:
            # update MTU or network type of interface
            values = {
                'ihost_uuid': controller.uuid,
                'ifname': self.management_interface,
                'imtu': self.management_mtu,
                'ifclass': interface_class,
                'networks': str(network.id),
            }
            self._update_interface_config(client, values)

        if self.management_vlan:
            mgmt_network = self._get_network(
                client, sysinv_constants.NETWORK_TYPE_MGMT)
            values = {
                'ihost_uuid': controller.uuid,
                'ifname': self.management_interface_name,
                'imtu': self.management_mtu,
                'iftype': sysinv_constants.INTERFACE_TYPE_VLAN,
                'ifclass': interface_class,
                'networks': [str(mgmt_network.id)],
                'uses': [self.management_interface],
                'vlan_id': self.management_vlan,
            }
            client.sysinv.iinterface.create(**values)
        elif self.subcloud_config():
            # Create a route to the system controller.
            # For managament vlan case, route will get
            # created upon interface creation if subcloud config.
            management_interface = self._get_interface(
                client, controller.uuid, self.management_interface_name)
            values = {
                'interface_uuid': management_interface.uuid,
                'network': str(self.system_controller_subnet.ip),
                'prefix': self.system_controller_subnet.prefixlen,
                'gateway': str(self.management_gateway_address),
                'metric': 1,
            }
            client.sysinv.route.create(**values)

    def _populate_infrastructure_interface(self, client, controller):
        """Configure the infrastructure interface(s)"""
        if not self.infrastructure_interface:
            return  # No infrastructure interface configured

        interface_class = sysinv_constants.INTERFACE_CLASS_PLATFORM
        network = self._get_network(client,
                                    sysinv_constants.NETWORK_TYPE_INFRA)

        if self.lag_infrastructure_interface:
            members = [self.lag_infrastructure_interface_member0]
            if self.lag_infrastructure_interface_member1:
                members.append(self.lag_infrastructure_interface_member1)

            aemode = self._get_interface_aemode(
                self.lag_infrastructure_interface_policy)

            txhashpolicy = self._get_interface_txhashpolicy(
                self.lag_infrastructure_interface_policy)

            values = {
                'ihost_uuid': controller.uuid,
                'ifname': self.infrastructure_interface,
                'imtu': self._get_interface_mtu(self.infrastructure_interface),
                'iftype': sysinv_constants.INTERFACE_TYPE_AE,
                'aemode': aemode,
                'txhashpolicy': txhashpolicy,
                'ifclass': interface_class,
                'networks': [str(network.id)],
                'uses': members,
            }

            client.sysinv.iinterface.create(**values)
        else:
            # update MTU or network type of interface
            values = {
                'ihost_uuid': controller.uuid,
                'ifname': self.infrastructure_interface,
            }
            values.update({
                'imtu': self._get_interface_mtu(self.infrastructure_interface)
            })
            if not self.infrastructure_vlan:
                values.update({
                    'ifclass': interface_class,
                    'networks': str(network.id)
                })

            self._update_interface_config(client, values)

        if self.infrastructure_vlan:
            values = {
                'ihost_uuid': controller.uuid,
                'ifname': self.infrastructure_interface_name,
                'imtu': self.infrastructure_mtu,
                'iftype': sysinv_constants.INTERFACE_TYPE_VLAN,
                'ifclass': interface_class,
                'networks': [str(network.id)],
                'uses': [self.infrastructure_interface],
                'vlan_id': self.infrastructure_vlan,
            }
            client.sysinv.iinterface.create(**values)

    def _populate_cluster_host_interface(self, client, controller):
        """Configure the cluster host interface(s)"""
        network = self._get_network(client,
                                    sysinv_constants.NETWORK_TYPE_CLUSTER_HOST)

        if (self.lag_cluster_host_interface and
            self.cluster_host_interface_name !=
                self.management_interface_name):
            members = [self.lag_cluster_host_interface_member0]
            if self.lag_cluster_host_interface_member1:
                members.append(self.lag_cluster_host_interface_member1)

            aemode = self._get_interface_aemode(
                self.lag_cluster_host_interface_policy)

            txhashpolicy = self._get_interface_txhashpolicy(
                self.lag_cluster_host_interface_policy)

            values = {
                'ihost_uuid': controller.uuid,
                'ifname': self.cluster_host_interface,
                'imtu': self._get_interface_mtu(self.cluster_host_interface),
                'iftype': sysinv_constants.INTERFACE_TYPE_AE,
                'aemode': aemode,
                'txhashpolicy': txhashpolicy,
                'ifclass': sysinv_constants.INTERFACE_CLASS_PLATFORM,
                'networks': [str(network.id)],
                'uses': members,
            }
            client.sysinv.iinterface.create(**values)
        else:
            # update MTU or network type of interface
            values = {
                'ihost_uuid': controller.uuid,
                'ifname': self.cluster_host_interface,
            }
            values.update({
                'imtu': self._get_interface_mtu(self.cluster_host_interface)
            })
            if not self.cluster_host_vlan:
                values.update({
                    'ifclass': sysinv_constants.INTERFACE_CLASS_PLATFORM,
                    'networks_to_add': str(network.id),
                })
            self._update_interface_config(client, values)

        if self.cluster_host_vlan:
            if (self.cluster_host_interface_name !=
                    self.management_interface_name):
                values = {
                    'ihost_uuid': controller.uuid,
                    'ifname': self.cluster_host_interface_name,
                    'imtu': self.cluster_host_mtu,
                    'iftype': sysinv_constants.INTERFACE_TYPE_VLAN,
                    'ifclass': sysinv_constants.INTERFACE_CLASS_PLATFORM,
                    'networks': [str(network.id)],
                    'uses': [self.cluster_host_interface],
                    'vlan_id': self.cluster_host_vlan,
                }
                client.sysinv.iinterface.create(**values)
            else:
                values = {
                    'ihost_uuid': controller.uuid,
                    'ifname': self.cluster_host_interface_name,
                    'ifclass': sysinv_constants.INTERFACE_CLASS_PLATFORM,
                    'networks_to_add': str(network.id),
                }
                self._update_interface_config(client, values)

    def _populate_oam_interface(self, client, controller):
        """Configure the OAM interface(s)"""

        network = self._get_network(client,
                                    sysinv_constants.NETWORK_TYPE_OAM)

        if self.lag_external_oam_interface:
            members = [self.lag_external_oam_interface_member0]
            if self.lag_external_oam_interface_member1:
                members.append(self.lag_external_oam_interface_member1)

            aemode = self._get_interface_aemode(
                self.lag_external_oam_interface_policy)

            txhashpolicy = self._get_interface_txhashpolicy(
                self.lag_external_oam_interface_policy)

            values = {
                'ihost_uuid': controller.uuid,
                'ifname': self.external_oam_interface,
                'imtu': self._get_interface_mtu(self.external_oam_interface),
                'iftype': sysinv_constants.INTERFACE_TYPE_AE,
                'aemode': aemode,
                'txhashpolicy': txhashpolicy,
                'ifclass': sysinv_constants.INTERFACE_CLASS_PLATFORM,
                'networks': [str(network.id)],
                'uses': members,
            }

            client.sysinv.iinterface.create(**values)
        else:
            # update MTU or network type of interface
            values = {
                'ihost_uuid': controller.uuid,
                'ifname': self.external_oam_interface,
                'ifclass': sysinv_constants.INTERFACE_CLASS_PLATFORM,
            }
            values.update({
                'imtu': self._get_interface_mtu(self.external_oam_interface)
            })
            if not self.external_oam_vlan:
                values.update({
                    'networks': str(network.id),
                })

            self._update_interface_config(client, values)

        if self.external_oam_vlan:
            values = {
                'ihost_uuid': controller.uuid,
                'ifname': self.external_oam_interface_name,
                'imtu': self.external_oam_mtu,
                'iftype': sysinv_constants.INTERFACE_TYPE_VLAN,
                'ifclass': sysinv_constants.INTERFACE_CLASS_PLATFORM,
                'networks': [str(network.id)],
                'uses': [self.external_oam_interface],
                'vlan_id': self.external_oam_vlan,
            }
            client.sysinv.iinterface.create(**values)

    def _populate_load_config(self, client):
        patch = {'software_version': SW_VERSION, "compatible_version": "N/A",
                 "required_patches": "N/A"}
        client.sysinv.load.create(**patch)

    def _populate_dns_config(self, client):
        # Retrieve the list of dns servers to get the uuid
        dns_list = client.sysinv.idns.list()
        dns_record = dns_list[0]
        values = {
            'nameservers': self.get_dns_servers(),
            'action': 'apply'
        }
        patch = sysinv.dict_to_patch(values)
        client.sysinv.idns.update(dns_record.uuid, patch)

    def _populate_docker_config(self, client):
        if self.enable_docker_proxy:
            proxy_parameter = {}
            if self.docker_http_proxy:
                proxy_parameter['http_proxy'] = self.docker_http_proxy
            if self.docker_https_proxy:
                proxy_parameter['https_proxy'] = self.docker_https_proxy
            if self.docker_no_proxy:
                proxy_parameter['no_proxy'] = self.docker_no_proxy

            if proxy_parameter:
                client.sysinv.service_parameter.create(
                    sysinv_constants.SERVICE_TYPE_DOCKER,
                    sysinv_constants.SERVICE_PARAM_SECTION_DOCKER_PROXY,
                    None,
                    None,
                    proxy_parameter
                )

        if not self.docker_use_default_registry:
            registry_parameter = {}
            if self.docker_k8s_registry:
                registry_parameter['k8s'] = \
                    self.docker_k8s_registry

            if self.docker_gcr_registry:
                registry_parameter['gcr'] = \
                    self.docker_gcr_registry

            if self.docker_quay_registry:
                registry_parameter['quay'] = \
                    self.docker_quay_registry

            if self.docker_docker_registry:
                registry_parameter['docker'] = \
                    self.docker_docker_registry

            if not self.is_secure_registry:
                registry_parameter['insecure_registry'] = "True"

            if registry_parameter:
                client.sysinv.service_parameter.create(
                    sysinv_constants.SERVICE_TYPE_DOCKER,
                    sysinv_constants.
                    SERVICE_PARAM_SECTION_DOCKER_REGISTRY,
                    None,
                    None,
                    registry_parameter
                )

    def populate_initial_config(self):
        """Populate initial system inventory configuration"""
        try:
            with openstack.OpenStack() as client:
                self._populate_system_config(client)
                self._populate_load_config(client)
                self._populate_network_config(client)
                if self.kubernetes:
                    self._populate_dns_config(client)
                    self._populate_docker_config(client)
                controller = self._populate_controller_config(client)
                # ceph_mon config requires controller host to be created
                self._inventory_config_complete_wait(client, controller)
                self._populate_interface_config(client, controller)

        except (KeystoneFail, SysInvFail) as e:
            LOG.exception(e)
            raise ConfigFail("Failed to provision initial system "
                             "configuration")

    def create_puppet_config(self):
        try:
            utils.create_system_config()
            utils.create_host_config()
        except Exception as e:
            LOG.exception(e)
            raise ConfigFail("Failed to update hiera configuration")

    def provision(self, configfile):
        """Perform system provisioning only"""
        if not self.labmode:
            raise ConfigFail("System provisioning only available with "
                             "lab mode enabled")
        if not configfile:
            raise ConfigFail("Missing input configuration file")
        self.input_config_from_file(configfile)
        self.populate_initial_config()

    def configure(self, configfile=None, default_config=False,
                  display_config=True):
        """Configure initial controller node."""
        if (os.path.exists(constants.CGCS_CONFIG_FILE) or
                os.path.exists(constants.CONFIG_PERMDIR) or
                os.path.exists(constants.INITIAL_CONFIG_COMPLETE_FILE)):
            raise ConfigFail("Configuration has already been done "
                             "and cannot be repeated.")

        try:
            with open(os.devnull, "w") as fnull:
                subprocess.check_call(["vgdisplay", "cgts-vg"], stdout=fnull,
                                      stderr=fnull)
        except subprocess.CalledProcessError:
            LOG.error("The cgts-vg volume group was not found")
            raise ConfigFail("Volume groups not configured")

        if default_config:
            self.default_config()
        elif not configfile:
            self.input_config()
        else:
            self.input_config_from_file(configfile)

        if display_config:
            self.display_config()

        # Validate Openstack passwords loaded in via config
        if configfile:
            self.process_validation_passwords()

        if not configfile and not default_config:
            while True:
                user_input = input(
                    "\nApply the above configuration? [y/n]: ")
                if user_input.lower() == 'q':
                    raise UserQuit
                elif user_input.lower() == 'y':
                    break
                elif user_input.lower() == 'n':
                    raise UserQuit
                else:
                    print("Invalid choice")

        # Verify at most one branding tarball is present
        self.verify_branding()

        self.write_config_file()
        utils.write_simplex_flag()

        print("\nApplying configuration (this will take several minutes):")

        runner = progress.ProgressRunner()
        runner.add(self.create_bootstrap_config,
                   'Creating bootstrap configuration')
        runner.add(self.apply_bootstrap_manifest,
                   "Applying bootstrap manifest")
        runner.add(self.persist_local_config,
                   'Persisting local configuration')
        runner.add(self.populate_initial_config,
                   'Populating initial system inventory')
        runner.add(self.create_puppet_config,
                   'Creating system configuration')
        runner.add(self.apply_controller_manifest,
                   'Applying controller manifest')
        runner.add(self.finalize_controller_config,
                   'Finalize controller configuration')
        runner.add(self.wait_service_enable,
                   'Waiting for service activation')
        runner.run()

    def check_required_interfaces_status(self):
        if self.management_interface_configured:
            if not is_interface_up(self.management_interface):
                print('')
                if (self.system_mode !=
                        sysinv_constants.SYSTEM_MODE_DUPLEX_DIRECT
                        and self.system_mode !=
                        sysinv_constants.SYSTEM_MODE_SIMPLEX):
                    print(textwrap.fill(
                        "Warning: The interface (%s) is not operational "
                        "and some platform services will not start properly. "
                        "Bring up the interface to enable the required "
                        "services." % self.management_interface, 80))

        if self.infrastructure_interface_configured:
            if not is_interface_up(self.infrastructure_interface):
                if self.system_mode != \
                        sysinv_constants.SYSTEM_MODE_DUPLEX_DIRECT:
                    print('')
                    print(textwrap.fill(
                        "Warning: The interface (%s) is not operational "
                        "and some platform services will not start properly. "
                        "Bring up the interface to enable the required "
                        "services." % self.infrastructure_interface, 80))

        if self.external_oam_interface_configured:
            if not is_interface_up(self.external_oam_interface):
                print('')
                print(textwrap.fill(
                      "Warning: The interface (%s) is not operational "
                      "and some OAM services will not start properly. "
                      "Bring up the interface to enable the required "
                      "services." % self.external_oam_interface, 80))
