#
# Copyright (c) 2014-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Utilities
"""

import collections
import errno
import glob
import os
import shutil
import socket
import subprocess
import time
import sys
import yaml

from six.moves import configparser
import re
import six

import netaddr
from tsconfig import tsconfig
from sysinv.common import constants as sysinv_constants

from controllerconfig.common import constants
from controllerconfig.common import log
from controllerconfig.common.exceptions import ValidateFail

LOOPBACK_IFNAME = 'lo'

NETWORK_SCRIPTS_PATH = '/etc/sysconfig/network-scripts'
NETWORK_SCRIPTS_PREFIX = 'ifcfg'
NETWORK_SCRIPTS_LOOPBACK = '%s-%s' % (NETWORK_SCRIPTS_PREFIX, LOOPBACK_IFNAME)

BOND_MIIMON_DEFAULT = 100


LOG = log.get_logger(__name__)

DEVNULL = open(os.devnull, 'w')

EXPECTED_SERVICE_NAME_AND_TYPE = (
    {"KEYSTONE_SERVICE_NAME": "keystone",
     "KEYSTONE_SERVICE_TYPE": "identity",
     "SYSINV_SERVICE_NAME": "sysinv",
     "SYSINV_SERVICE_TYPE": "platform",
     "PATCHING_SERVICE_NAME": "patching",
     "PATCHING_SERVICE_TYPE": "patching",
     "NFV_SERVICE_NAME": "vim",
     "NFV_SERVICE_TYPE": "nfv",
     "FM_SERVICE_NAME": "fm",
     "FM_SERVICE_TYPE": "faultmanagement",
     "BARBICAN_SERVICE_NAME": "barbican",
     "BARBICAN_SERVICE_TYPE": "key-manager",
     })


def filesystem_get_free_space(path):
    """ Get Free space of directory """
    statvfs = os.statvfs(path)
    return (statvfs.f_frsize * statvfs.f_bavail)


def directory_get_size(start_dir, regex=None):
    """
    Get total size of a directory tree in bytes
    :param start_dir: top of tree
    :param regex: only include files matching this regex (if provided)
    :return: size in bytes
    """
    total_size = 0
    for dirpath, _, filenames in os.walk(start_dir):
        for filename in filenames:
            if regex is None or regex.match(filename):
                filep = os.path.join(dirpath, filename)
                try:
                    total_size += os.path.getsize(filep)
                except OSError as e:
                    if e.errno != errno.ENOENT:
                        raise e
    return total_size


def print_bytes(sizeof):
    """ Pretty print bytes """
    for size in ['Bytes', 'KB', 'MB', 'GB', 'TB']:
        if abs(sizeof) < 1024.0:
            return "%3.1f %s" % (sizeof, size)
        sizeof /= 1024.0


def modprobe_drbd():
    """Load DRBD module"""
    try:
        mod_parms = subprocess.check_output(['drbdadm', 'sh-mod-parms'],
                                            close_fds=True).rstrip()
        subprocess.call(["modprobe", "-s", "drbd", mod_parms], stdout=DEVNULL)

    except subprocess.CalledProcessError:
        LOG.error("Failed to load drbd module")
        raise


def drbd_start(resource):
    """Start drbd resource"""
    try:
        subprocess.check_call(["drbdadm", "up", resource],
                              stdout=DEVNULL)

        subprocess.check_call(["drbdadm", "primary", resource],
                              stdout=DEVNULL)

    except subprocess.CalledProcessError:
        LOG.error("Failed to start drbd %s" % resource)
        raise


def drbd_stop(resource):
    """Stop drbd resource"""
    try:
        subprocess.check_call(["drbdadm", "secondary", resource],
                              stdout=DEVNULL)
        # Allow time for demotion to be processed
        time.sleep(1)
        subprocess.check_call(["drbdadm", "down", resource], stdout=DEVNULL)

    except subprocess.CalledProcessError:
        LOG.error("Failed to stop drbd %s" % resource)
        raise


def mount(device, directory):
    """Mount a directory"""
    try:
        subprocess.check_call(["mount", device, directory], stdout=DEVNULL)

    except subprocess.CalledProcessError:
        LOG.error("Failed to mount %s filesystem" % directory)
        raise


def umount(directory):
    """Unmount a directory"""
    try:
        subprocess.check_call(["umount", directory], stdout=DEVNULL)

    except subprocess.CalledProcessError:
        LOG.error("Failed to umount %s filesystem" % directory)
        raise


def start_service(name):
    """ Start a systemd service """
    try:
        subprocess.check_call(["systemctl", "start", name], stdout=DEVNULL)
    except subprocess.CalledProcessError:
        LOG.error("Failed to start %s service" % name)
        raise


def stop_service(name):
    """ Stop a systemd service """
    try:
        subprocess.check_call(["systemctl", "stop", name], stdout=DEVNULL)
    except subprocess.CalledProcessError:
        LOG.error("Failed to stop %s service" % name)
        raise


def restart_service(name):
    """ Restart a systemd service """
    try:
        subprocess.check_call(["systemctl", "restart", name], stdout=DEVNULL)
    except subprocess.CalledProcessError:
        LOG.error("Failed to restart %s service" % name)
        raise


def start_lsb_service(name):
    """ Start a Linux Standard Base service """
    try:
        script = os.path.join("/etc/init.d", name)
        # Call the script with SYSTEMCTL_SKIP_REDIRECT=1 in the environment
        subprocess.check_call([script, "start"],
                              env=dict(os.environ,
                                       **{"SYSTEMCTL_SKIP_REDIRECT": "1"}),
                              stdout=DEVNULL)
    except subprocess.CalledProcessError:
        LOG.error("Failed to start %s service" % name)
        raise


def stop_lsb_service(name):
    """ Stop a Linux Standard Base service """
    try:
        script = os.path.join("/etc/init.d", name)
        # Call the script with SYSTEMCTL_SKIP_REDIRECT=1 in the environment
        subprocess.check_call([script, "stop"],
                              env=dict(os.environ,
                                       **{"SYSTEMCTL_SKIP_REDIRECT": "1"}),
                              stdout=DEVNULL)
    except subprocess.CalledProcessError:
        LOG.error("Failed to stop %s service" % name)
        raise


def restart_lsb_service(name):
    """ Restart a Linux Standard Base service """
    try:
        script = os.path.join("/etc/init.d", name)
        # Call the script with SYSTEMCTL_SKIP_REDIRECT=1 in the environment
        subprocess.check_call([script, "restart"],
                              env=dict(os.environ,
                                       **{"SYSTEMCTL_SKIP_REDIRECT": "1"}),
                              stdout=DEVNULL)
    except subprocess.CalledProcessError:
        LOG.error("Failed to restart %s service" % name)
        raise


def check_sm_service(service, state):
    """ Check whether an SM service has the supplied state """
    try:
        output = subprocess.check_output(["sm-query", "service", service])
        return state in output
    except subprocess.CalledProcessError:
        return False


def wait_sm_service(service, timeout=180):
    """ Check whether an SM service has been enabled.
    :param service: SM service name
    :param timeout: timeout in seconds
    :return True if the service is enabled, False otherwise
    """
    for _ in range(timeout):
        if check_sm_service(service, 'enabled-active'):
            return True
        time.sleep(1)
    return False


def is_active(service):
    """ Check whether an SM service is active """
    return check_sm_service(service, 'enabled-active')


def get_controller_hostname():
    """
    Get the hostname for this controller
    :return: controller hostname
    """
    return socket.gethostname()


def get_mate_controller_hostname():
    """
    Get the hostname for the mate controller
    :return: mate controller hostname
    """
    my_hostname = socket.gethostname()
    if my_hostname.endswith('-0'):
        postfix = '-1'
    elif my_hostname.endswith('-1'):
        postfix = '-0'
    else:
        raise Exception("Invalid controller hostname")
    return my_hostname.rsplit('-', 1)[0] + postfix


def get_address_from_hosts_file(hostname):
    """
    Get the IP address of a host from the /etc/hosts file
    :param hostname: hostname to look up
    :return: IP address of host
    """
    hosts = open('/etc/hosts')
    for line in hosts:
        if line.strip() and line.split()[1] == hostname:
            return line.split()[0]
    raise Exception("Hostname %s not found in /etc/hosts" % hostname)


def validate_and_normalize_mac(address):
    """Validate a MAC address and return normalized form.

    Checks whether the supplied MAC address is formally correct and
    normalize it to all lower case.

    :param address: MAC address to be validated and normalized.
    :returns: Normalized and validated MAC address.
    :raises: InvalidMAC If the MAC address is not valid.

    """
    if not is_valid_mac(address):
        raise Exception("InvalidMAC %s" % address)
    return address.lower()


def is_valid_ip(address):
    if not is_valid_ipv4(address):
        return is_valid_ipv6(address)
    return True


def lag_mode_to_str(lag_mode):
    if lag_mode == 0:
        return "balance-rr"
    if lag_mode == 1:
        return "active-backup"
    elif lag_mode == 2:
        return "balance-xor"
    elif lag_mode == 3:
        return "broadcast"
    elif lag_mode == 4:
        return "802.3ad"
    elif lag_mode == 5:
        return "balance-tlb"
    elif lag_mode == 6:
        return "balance-alb"
    else:
        raise Exception(
            "Invalid LAG_MODE value of %d. Valid values: 0-6" % lag_mode)


def is_combined_load():
    return 'worker' in tsconfig.subfunctions


def get_system_type():
    if is_combined_load():
        return sysinv_constants.TIS_AIO_BUILD
    return sysinv_constants.TIS_STD_BUILD


def get_security_profile():
    eprofile = sysinv_constants.SYSTEM_SECURITY_PROFILE_EXTENDED
    if tsconfig.security_profile == eprofile:
        return eprofile
    return sysinv_constants.SYSTEM_SECURITY_PROFILE_STANDARD


def is_cpe():
    return get_system_type() == sysinv_constants.TIS_AIO_BUILD


def get_interface_config_common(device, mtu=None):
    """
    Return the interface configuration parameters that is common to all
    device types.
    """
    parameters = collections.OrderedDict()
    parameters['BOOTPROTO'] = 'none'
    parameters['ONBOOT'] = 'yes'
    parameters['DEVICE'] = device
    # Increased to accommodate devices that require more time to
    # complete link auto-negotiation
    parameters['LINKDELAY'] = '20'
    if mtu:
        parameters['MTU'] = mtu
    return parameters


def get_interface_config_ipv4(ip_address, ip_subnet, ip_gateway):
    """
    Return the interface configuration parameters for all IPv4 static
    addressing.
    """
    parameters = collections.OrderedDict()
    parameters['IPADDR'] = ip_address
    parameters['NETMASK'] = ip_subnet.netmask
    parameters['BROADCAST'] = ip_subnet.broadcast
    if ip_gateway:
        parameters['GATEWAY'] = ip_gateway
    return parameters


def get_interface_config_ipv6(ip_address, ip_subnet, ip_gateway):
    """
    Return the interface configuration parameters for all IPv6 static
    addressing.
    """
    parameters = collections.OrderedDict()
    parameters['IPV6INIT'] = 'yes'
    parameters['IPV6ADDR'] = netaddr.IPNetwork('%s/%u' % (ip_address,
                                                          ip_subnet.prefixlen))
    if ip_gateway:
        parameters['IPV6_DEFAULTGW'] = ip_gateway
    return parameters


def get_interface_config_static(ip_address, ip_subnet, ip_gateway=None):
    """
    Return the interface configuration parameters for all IP static
    addressing.
    """
    if netaddr.IPAddress(ip_address).version == 4:
        return get_interface_config_ipv4(ip_address, ip_subnet, ip_gateway)
    else:
        return get_interface_config_ipv6(ip_address, ip_subnet, ip_gateway)


def write_interface_config_file(device, parameters):
    """
    Write interface configuration parameters to the network scripts
    directory named after the supplied device.

    :param device device name as str
    :param parameters dict of parameters
    """
    filename = os.path.join(NETWORK_SCRIPTS_PATH, "%s-%s" %
                            (NETWORK_SCRIPTS_PREFIX, device))
    try:
        with open(filename, 'w') as f:
            for parameter, value in parameters.items():
                f.write("%s=%s\n" % (parameter, str(value)))
    except IOError:
        LOG.error("Failed to create file: %s" % filename)
        raise


def write_interface_config_ethernet(device, mtu=None, parameters=None):
    """Write the interface configuration for an Ethernet device."""
    config = get_interface_config_common(device, mtu)
    if parameters:
        config.update(parameters)
    write_interface_config_file(device, config)


def write_interface_config_vlan(device, mtu, parameters=None):
    """Write the interface configuration for a VLAN device."""
    config = get_interface_config_vlan()
    if parameters:
        config.update(parameters)
    write_interface_config_ethernet(device, mtu, parameters=config)


def write_interface_config_slave(device, master, parameters=None):
    """Write the interface configuration for a bond slave device."""
    config = get_interface_config_slave(master)
    if parameters:
        config.update(parameters)
    write_interface_config_ethernet(device, parameters=config)


def write_interface_config_bond(device, mtu, mode, txhash, miimon,
                                member1, member2, parameters=None):
    """Write the interface configuration for a bond master device."""
    config = get_interface_config_bond(mode, txhash, miimon)
    if parameters:
        config.update(parameters)
    write_interface_config_ethernet(device, mtu, parameters=config)

    # create slave device configuration files
    if member1:
        write_interface_config_slave(member1, device)
    if member2:
        write_interface_config_slave(member2, device)


def get_interface_config_vlan():
    """
    Return the interface configuration parameters for all IP static
    addressing.
    """
    parameters = collections.OrderedDict()
    parameters['VLAN'] = 'yes'
    return parameters


def get_interface_config_slave(master):
    """
    Return the interface configuration parameters for bond interface
    slave devices.
    """
    parameters = collections.OrderedDict()
    parameters['MASTER'] = master
    parameters['SLAVE'] = 'yes'
    parameters['PROMISC'] = 'yes'
    return parameters


def get_interface_config_bond(mode, txhash, miimon):
    """
    Return the interface configuration parameters for bond interface
    master devices.
    """
    options = "mode=%s miimon=%s" % (mode, miimon)

    if txhash:
        options += " xmit_hash_policy=%s" % txhash

    if mode == constants.LAG_MODE_8023AD:
        options += " lacp_rate=fast"

    parameters = collections.OrderedDict()
    parameters['BONDING_OPTS'] = "\"%s\"" % options
    return parameters


def remove_interface_config_files(stdout=None, stderr=None):
    """
    Remove all existing interface configuration files.
    """
    files = glob.glob1(NETWORK_SCRIPTS_PATH, "%s-*" % NETWORK_SCRIPTS_PREFIX)
    for file in [f for f in files if f != NETWORK_SCRIPTS_LOOPBACK]:
        ifname = file[len(NETWORK_SCRIPTS_PREFIX) + 1:]  # remove prefix
        subprocess.check_call(["ifdown", ifname],
                              stdout=stdout, stderr=stderr)
        os.remove(os.path.join(NETWORK_SCRIPTS_PATH, file))


def remove_interface_ip_address(device, ip_address, ip_subnet,
                                stdout=None, stderr=None):
    """Remove an IP address from an interface"""
    subprocess.check_call(
        ["ip", "addr", "del",
         str(ip_address) + "/" + str(ip_subnet.prefixlen),
         "dev", device],
        stdout=stdout, stderr=stderr)


def send_interface_garp(device, ip_address, stdout=None, stderr=None):
    """Send a GARP message for the supplied address"""
    subprocess.call(
        ["arping", "-c", "3", "-A", "-q", "-I",
         device, str(ip_address)],
        stdout=stdout, stderr=stderr)


def restart_networking(stdout=None, stderr=None):
    """
    Restart networking services.
    """
    # Kill any leftover dhclient process from the boot
    subprocess.call(["pkill", "dhclient"])

    # remove any existing IP addresses
    ifs = glob.glob1('/sys/class/net', "*")
    for i in [i for i in ifs if i != LOOPBACK_IFNAME]:
        subprocess.call(
            ["ip", "link", "set", "dev", i, "down"])
        subprocess.call(
            ["ip", "addr", "flush", "dev", i])
        subprocess.call(
            ["ip", "-6", "addr", "flush", "dev", i])

    subprocess.check_call(["systemctl", "restart", "network"],
                          stdout=stdout, stderr=stderr)


def output_to_dict(output):
    dict = {}
    output = [_f for _f in output.split('\n') if _f]

    for row in output:
        values = row.split()
        if len(values) != 2:
            raise Exception("The following output does not respect the "
                            "format: %s" % row)
        dict[values[1]] = values[0]

    return dict


def get_install_uuid():
    """ Get the install uuid from the feed directory. """
    uuid_fname = None
    try:
        uuid_dir = '/www/pages/feed/rel-' + tsconfig.SW_VERSION
        uuid_fname = os.path.join(uuid_dir, 'install_uuid')
        with open(uuid_fname, 'r') as uuid_file:
            install_uuid = uuid_file.readline().rstrip()
    except IOError:
        LOG.error("Failed to open file: %s", uuid_fname)
        raise Exception("Failed to retrieve install UUID")

    return install_uuid


def write_simplex_flag():
    """ Write simplex flag. """
    simplex_flag = "/etc/platform/simplex"
    try:
        open(simplex_flag, 'w')
    except IOError:
        LOG.error("Failed to open file: %s", simplex_flag)
        raise Exception("Failed to write configuration file")


def create_manifest_runtime_config(filename, config):
    """Write the runtime Puppet configuration to a runtime file."""
    if not config:
        return
    try:
        with open(filename, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
    except Exception:
        LOG.exception("failed to write config file: %s" % filename)
        raise


def apply_manifest(controller_address_0, personality, manifest, hieradata,
                   stdout_progress=False, runtime_filename=None):
    """Apply puppet manifest files."""

    # FIXME(mpeters): remove once manifests and modules are not dependent
    # on checking the primary config condition
    os.environ["INITIAL_CONFIG_PRIMARY"] = "true"

    cmd = [
        "/usr/local/bin/puppet-manifest-apply.sh",
        hieradata,
        str(controller_address_0),
        personality,
        manifest
    ]

    if runtime_filename:
        cmd.append((runtime_filename))

    logfile = "/tmp/apply_manifest.log"
    try:
        with open(logfile, "w") as flog:
            subprocess.check_call(cmd, stdout=flog, stderr=flog)
    except subprocess.CalledProcessError:
        msg = "Failed to execute %s manifest" % manifest
        print(msg)
        raise Exception(msg)


def create_system_controller_config(filename):
    """ Create any additional parameters needed for system controller"""
    # set keystone endpoint region name and sysinv keystone authtoken
    # region name
    config = {
        'keystone::endpoint::region':
            sysinv_constants.SYSTEM_CONTROLLER_REGION,
        'sysinv::region_name':
            sysinv_constants.SYSTEM_CONTROLLER_REGION,
    }
    try:
        with open(filename, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
    except Exception:
        LOG.exception("failed to write config file: %s" % filename)
        raise


def create_static_config():
    cmd = ["/usr/bin/sysinv-puppet",
           "create-static-config",
           constants.HIERADATA_WORKDIR]
    try:
        os.makedirs(constants.HIERADATA_WORKDIR)
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError:
        msg = "Failed to create puppet hiera static config"
        print(msg)
        raise Exception(msg)


def create_system_config():
    cmd = ["/usr/bin/sysinv-puppet",
           "create-system-config",
           constants.HIERADATA_PERMDIR]
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError:
        msg = "Failed to update puppet hiera system config"
        print(msg)
        raise Exception(msg)


def create_host_config(hostname=None):
    cmd = ["/usr/bin/sysinv-puppet",
           "create-host-config",
           constants.HIERADATA_PERMDIR]
    if hostname:
        cmd.append(hostname)

    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError:
        msg = "Failed to update puppet hiera host config"
        print(msg)
        raise Exception(msg)


def shutdown_file_systems():
    """ Shutdown filesystems """

    umount("/var/lib/postgresql")
    drbd_stop("drbd-pgsql")

    umount("/opt/platform")
    drbd_stop("drbd-platform")

    stop_service("www-pages-helm_charts.mount")
    umount("/opt/cgcs")
    drbd_stop("drbd-cgcs")

    umount("/opt/extension")
    drbd_stop("drbd-extension")

    if os.path.exists("/opt/patch-vault"):
        umount("/opt/patch-vault")
        drbd_stop("drbd-patch-vault")

    umount("/var/lib/rabbitmq")
    drbd_stop("drbd-rabbit")

    stop_service("etcd.service")
    stop_service("opt-etcd.mount")
    drbd_stop("drbd-etcd")

    umount("/var/lib/docker-distribution")
    drbd_stop("drbd-dockerdistribution")


def persist_config():
    """Copy temporary config files into new DRBD filesystem"""

    # Persist temporary keyring
    try:
        if os.path.isdir(constants.KEYRING_WORKDIR):
            shutil.move(constants.KEYRING_WORKDIR, constants.KEYRING_PERMDIR)
    except IOError:
        LOG.error("Failed to persist temporary keyring")
        raise Exception("Failed to persist temporary keyring")

    # Move puppet working files into permanent directory
    try:
        # ensure parent directory is present
        subprocess.call(["mkdir", "-p", tsconfig.PUPPET_PATH])

        # move hiera data to puppet directory
        if os.path.isdir(constants.HIERADATA_WORKDIR):
            subprocess.check_call(["mv", constants.HIERADATA_WORKDIR,
                                  tsconfig.PUPPET_PATH])
    except subprocess.CalledProcessError:
        LOG.error("Failed to persist puppet config files")
        raise Exception("Failed to persist puppet config files")

    # Move config working files into permanent directory
    try:
        # ensure parent directory is present
        subprocess.call(["mkdir", "-p",
                         os.path.dirname(constants.CONFIG_PERMDIR)])

        if os.path.isdir(constants.CONFIG_WORKDIR):
            # Remove destination directory in case it was created previously
            subprocess.call(["rm", "-rf", constants.CONFIG_PERMDIR])

            # move working data to config directory
            subprocess.check_call(["mv", constants.CONFIG_WORKDIR,
                                   constants.CONFIG_PERMDIR])
    except subprocess.CalledProcessError:
        LOG.error("Failed to persist config files")
        raise Exception("Failed to persist config files")

    # Copy postgres config files for mate
    try:
        subprocess.check_call(["mkdir",
                               constants.CONFIG_PERMDIR + "/postgresql"])
    except subprocess.CalledProcessError:
        LOG.error("Failed to create postgresql dir")
        raise Exception("Failed to persist config files")

    try:
        for f in glob.glob("/etc/postgresql/*.conf"):
            subprocess.check_call([
                "cp", "-p", f, constants.CONFIG_PERMDIR + "/postgresql/"])
    except IOError:
        LOG.error("Failed to persist postgresql config files")
        raise Exception("Failed to persist config files")

    # Set up replicated directory for PXE config files
    try:
        subprocess.check_call([
            "mkdir", "-p", constants.CONFIG_PERMDIR + "/pxelinux.cfg"])
    except subprocess.CalledProcessError:
        LOG.error("Failed to create persistent pxelinux.cfg directory")
        raise Exception("Failed to persist config files")

    try:
        subprocess.check_call(["ln", "-s", constants.CONFIG_PERMDIR +
                               "/pxelinux.cfg", "/pxeboot/pxelinux.cfg"])
    except subprocess.CalledProcessError:
        LOG.error("Failed to create pxelinux.cfg symlink")
        raise Exception("Failed to persist config files")

    # Copy branding tarball for mate
    if os.listdir('/opt/branding'):
        try:
            subprocess.check_call([
                "mkdir", constants.CONFIG_PERMDIR + "/branding"])
        except subprocess.CalledProcessError:
            LOG.error("Failed to create branding dir")
            raise Exception("Failed to persist config files")

        try:
            for f in glob.glob("/opt/branding/*.tgz"):
                subprocess.check_call([
                    "cp", "-p", f, constants.CONFIG_PERMDIR + "/branding/"])
                break
        except IOError:
            LOG.error("Failed to persist branding config files")
            raise Exception("Failed to persist config files")


def apply_banner_customization():
    """ Apply and Install banners provided by the user """
    """ execute: /usr/sbin/apply_banner_customization """
    logfile = "/tmp/apply_banner_customization.log"
    try:
        with open(logfile, "w") as blog:
            subprocess.check_call(["/usr/sbin/apply_banner_customization",
                                   "/opt/banner"],
                                  stdout=blog, stderr=blog)
    except subprocess.CalledProcessError:
        error_text = "Failed to apply banner customization"
        print("%s; see %s for detail" % (error_text, logfile))


def mtce_restart():
    """Restart maintenance processes to handle interface changes"""
    restart_service("mtcClient")
    restart_service("hbsClient")
    restart_service("pmon")


def mark_config_complete():
    """Signal initial configuration has been completed"""
    try:
        subprocess.check_call(["touch",
                               constants.INITIAL_CONFIG_COMPLETE_FILE])
        subprocess.call(["rm", "-rf", constants.KEYRING_WORKDIR])

    except subprocess.CalledProcessError:
        LOG.error("Failed to mark initial config complete")
        raise Exception("Failed to mark initial config complete")


def configure_hostname(hostname):
    """Configure hostname for this host."""

    hostname_file = '/etc/hostname'
    try:
        with open(hostname_file, 'w') as f:
            f.write(hostname + "\n")
    except IOError:
        LOG.error("Failed to update file: %s", hostname_file)
        raise Exception("Failed to configure hostname")

    try:
        subprocess.check_call(["hostname", hostname])
    except subprocess.CalledProcessError:
        LOG.error("Failed to update hostname %s" % hostname)
        raise Exception("Failed to configure hostname")


def progress(steps, step, action, result, newline=False):
    """Display progress."""
    if steps == 0:
        hashes = 45
        percentage = 100
    else:
        hashes = (step * 45) / steps
        percentage = (step * 100) / steps

    sys.stdout.write("\rStep {0:{width}d} of {1:d} [{2:45s}] "
                     "[{3:d}%]".format(min(step, steps), steps,
                                       '#' * hashes, percentage,
                                       width=len(str(steps))))
    if step == steps or newline:
        sys.stdout.write("\n")
    sys.stdout.flush()


def touch(fname):
    with open(fname, 'a'):
        os.utime(fname, None)


def is_ssh_parent():
    """Determine if current process is started from a ssh session"""
    command = ('pstree -s %d' % (os.getpid()))
    try:
        cmd_output = subprocess.check_output(command, shell=True)
        if "ssh" in cmd_output:
            return True
        else:
            return False
    except subprocess.CalledProcessError:
        return False


def is_valid_vlan(vlan):
    """Determine whether vlan is valid."""
    try:
        if 0 < int(vlan) < 4095:
            return True
        else:
            return False
    except (ValueError, TypeError):
        return False


def is_mtu_valid(mtu):
    """Determine whether a mtu is valid."""
    try:
        if int(mtu) < 576:
            return False
        elif int(mtu) > 9216:
            return False
        else:
            return True
    except (ValueError, TypeError):
        return False


def is_valid_hostname(hostname):
    """Determine whether a hostname is valid as per RFC 1123."""

    # Maximum length of 255
    if not hostname or len(hostname) > 255:
        return False
    # Allow a single dot on the right hand side
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    # Create a regex to ensure:
    # - hostname does not begin or end with a dash
    # - each segment is 1 to 63 characters long
    # - valid characters are A-Z (any case) and 0-9
    valid_re = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)  # noqa pylint: disable=anomalous-backslash-in-string
    return all(valid_re.match(x) for x in hostname.split("."))


def is_valid_mac(mac):
    """Verify the format of a MAC addres."""
    if not mac:
        return False
    m = "[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$"
    return isinstance(mac, six.string_types) and re.match(m, mac.lower())


def validate_network_str(network_str, minimum_size,
                         existing_networks=None, multicast=False):
    """Determine whether a network is valid."""
    try:
        network = netaddr.IPNetwork(network_str)
        if network.ip != network.network:
            raise ValidateFail("Invalid network address")
        elif network.size < minimum_size:
            raise ValidateFail("Subnet too small - must have at least %d "
                               "addresses" % minimum_size)
        elif network.version == 6 and network.prefixlen < 64:
            raise ValidateFail("IPv6 minimum prefix length is 64")
        elif existing_networks:
            if any(network.ip in subnet for subnet in existing_networks):
                raise ValidateFail("Subnet overlaps with another "
                                   "configured subnet")
        elif multicast and not network.is_multicast():
            raise ValidateFail("Invalid subnet - must be multicast")
        return network
    except netaddr.AddrFormatError:
        raise ValidateFail(
            "Invalid subnet - not a valid IP subnet")


def is_valid_filename(filename):
    return '\0' not in filename


def is_valid_by_path(filename):
    return "/dev/disk/by-path" in filename and "-part" not in filename


def is_valid_url(url_str):
    # Django URL validation patterns
    r = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)'  # domain...
        r'+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    url = r.match(url_str)
    if url:
        return True
    else:
        return False


def is_valid_domain(url_str):
    r = re.compile(
        r'^(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)'  # domain...
        r'+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'[A-Za-z0-9-_]*)'  # localhost, hostname
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    url = r.match(url_str)
    if url:
        return True
    else:
        return False


def is_valid_ipv4(address):
    """Verify that address represents a valid IPv4 address."""
    try:
        return netaddr.valid_ipv4(address)
    except Exception:
        return False


def is_valid_ipv6(address):
    try:
        return netaddr.valid_ipv6(address)
    except Exception:
        return False


def is_valid_domain_or_ip(url_str):
    if url_str:
        if is_valid_domain(url_str):
            return True
        ip_with_port = url_str.split(':')
        if len(ip_with_port) <= 2:
            # check ipv4 or ipv4 with port
            return is_valid_ipv4(ip_with_port[0])
        else:
            # check ipv6 with port
            if '[' in url_str:
                try:
                    bkt_idx = url_str.index(']')
                    if bkt_idx + 1 == len(url_str):
                        # brackets without port
                        return False
                    else:
                        return is_valid_ipv6(url_str[1:bkt_idx])
                except Exception:
                    return False
            else:
                # check ipv6 without port
                return is_valid_ipv6(url_str)
    else:
        return False


def is_valid_bool_str(val):
    """Check if the provided string is a valid bool string or not."""
    boolstrs = ('true', 'false')
    return str(val).lower() in boolstrs


def validate_address_str(ip_address_str, network):
    """Determine whether an address is valid."""
    try:
        ip_address = netaddr.IPAddress(ip_address_str)
        if ip_address.version != network.version:
            msg = ("Invalid IP version - must match network version " +
                   ip_version_to_string(network.version))
            raise ValidateFail(msg)
        elif ip_address == network:
            raise ValidateFail("Cannot use network address")
        elif ip_address == network.broadcast:
            raise ValidateFail("Cannot use broadcast address")
        elif ip_address not in network:
            raise ValidateFail(
                "Address must be in subnet %s" % str(network))
        return ip_address
    except netaddr.AddrFormatError:
        raise ValidateFail(
            "Invalid address - not a valid IP address")


def ip_version_to_string(ip_version):
    """Determine whether a nameserver address is valid."""
    if ip_version == 4:
        return "IPv4"
    elif ip_version == 6:
        return "IPv6"
    else:
        return "IP"


def validate_nameserver_address_str(ip_address_str, subnet_version=None):
    """Determine whether a nameserver address is valid."""
    try:
        ip_address = netaddr.IPAddress(ip_address_str)
        if subnet_version is not None and ip_address.version != subnet_version:
            msg = ("Invalid IP version - must match OAM subnet version " +
                   ip_version_to_string(subnet_version))
            raise ValidateFail(msg)
        return ip_address
    except netaddr.AddrFormatError:
        msg = "Invalid address - not a valid %s address" % \
              ip_version_to_string(subnet_version)
        raise ValidateFail(msg)


def validate_address(ip_address, network):
    """Determine whether an address is valid."""
    if ip_address.version != network.version:
            msg = ("Invalid IP version - must match network version " +
                   ip_version_to_string(network.version))
            raise ValidateFail(msg)
    elif ip_address == network:
        raise ValidateFail("Cannot use network address")
    elif ip_address == network.broadcast:
        raise ValidateFail("Cannot use broadcast address")
    elif ip_address not in network:
        raise ValidateFail("Address must be in subnet %s" % str(network))


def check_network_overlap(new_network, configured_networks):
    """ Validate that new_network does not overlap any configured_networks.
    """
    if any(new_network.ip in subnet for subnet in
           configured_networks):
        raise ValidateFail(
            "Subnet %s overlaps with another configured subnet" % new_network)


def validate_openstack_password(password, rules_file,
                                section="security_compliance"):
    try:
        config = configparser.RawConfigParser()
        parsed_config = config.read(rules_file)
        if not parsed_config:
            msg = ("Cannot parse rules file: %s" % rules_file)
            raise Exception(msg)
        if not config.has_section(section):
            msg = ("Required section '%s' not found in rules file" % section)
            raise Exception(msg)

        password_regex = get_optional(config, section, 'password_regex')
        password_regex_description = get_optional(config, section,
                                                  'password_regex_description')

        if not password_regex:
            msg = ("Required option 'password_regex' not found in "
                   "rule file: %s" % rules_file)
            raise Exception(msg)
        # Even if regex_description is not found, we will proceed
        # and give a generic failure warning instead
        if not password_regex_description:
            password_regex_description = ("Password does not meet "
                                          "complexity criteria")

        if not isinstance(password, six.string_types):
            msg = "Password must be a string type"
            raise Exception(msg)
        try:
            # config parser would read in the string as a literal
            # representation which would fail regex matching
            password_regex = password_regex.strip('"')
            if not re.match(password_regex, password):
                return False, password_regex_description
        except re.error:
            msg = ("Unable to validate password due to invalid "
                   "complexity criteria ('password_regex')")
            raise Exception(msg)
    except Exception:
        raise Exception("Password validation failed")
    return True, ""


def extract_openstack_password_rules_from_file(
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


def get_optional(conf, section, key):
    if conf.has_option(section, key):
        return conf.get(section, key)
    return None


def get_service(conf, section, key):
    if key in EXPECTED_SERVICE_NAME_AND_TYPE:
        if conf.has_option(section, key):
            value = conf.get(section, key)
            if value != EXPECTED_SERVICE_NAME_AND_TYPE[key]:
                raise ValidateFail("Unsupported %s: %s " % (key, value))
        else:
            value = EXPECTED_SERVICE_NAME_AND_TYPE[key]
        return value
    else:
        return conf.get(section, key)
