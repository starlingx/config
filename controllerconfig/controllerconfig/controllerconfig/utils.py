#
# Copyright (c) 2014-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Utilities
"""

import glob
import os
import shutil
import subprocess
import time
import yaml

import re
import six

import netaddr
from tsconfig import tsconfig

from controllerconfig.common import constants
from controllerconfig.common.exceptions import ValidateFail
from oslo_log import log

LOG = log.getLogger(__name__)

DEVNULL = open(os.devnull, 'w')


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


def check_sm_service(service, state):
    """ Check whether an SM service has the supplied state """
    try:
        output = subprocess.check_output(["sm-query", "service", service],
                                         universal_newlines=True)
        return state in output  # pylint: disable=unsupported-membership-test
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
                               "/pxelinux.cfg", "/var/pxeboot/pxelinux.cfg"])
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


def touch(fname):
    with open(fname, 'a'):
        os.utime(fname, None)


def is_ssh_parent():
    """Determine if current process is started from a ssh session"""
    command = ('pstree -s %d' % (os.getpid()))
    try:
        cmd_output = subprocess.check_output(command, shell=True,
                                             universal_newlines=True)
        if "ssh" in cmd_output:  # pylint: disable=unsupported-membership-test
            return True
        else:
            return False
    except subprocess.CalledProcessError:
        return False


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
        if network.size < minimum_size:
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
