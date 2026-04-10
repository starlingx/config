#
# Copyright (c) 2025-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# All Rights Reserved.
#

""" System Inventory Etcd Utilities and helper functions."""

import os
import re
import subprocess

from distutils.version import LooseVersion
from oslo_log import log

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import kubernetes
from sysinv.common import utils
from sysinv.common.utils import get_debian_codename

LOG = log.getLogger(__name__)

codename = get_debian_codename()

# Import ruamel.yaml based on Debian version
if codename == constants.OS_DEBIAN_BULLSEYE:
    import ruamel.yaml as yaml
    from ruamel.yaml.compat import StringIO
else:
    from ruamel.yaml import YAML
    from io import StringIO

ETCD_API_ENV_VAR = {"ETCDCTL_API": "3"}
ETCD_SNAPSHOT_FILE_NAME = "stx_etcd.snap"
ETCD_SNAPSHOT_FULL_FILE_PATH = os.path.join(
    kubernetes.KUBE_CONTROL_PLANE_ETCD_BACKUP_PATH, ETCD_SNAPSHOT_FILE_NAME)
ETCD_VERSION_FILE_NAME = "etcd_version"
ETCD_VERSION_FULL_FILE_PATH = os.path.join(
    kubernetes.KUBE_CONTROL_PLANE_ETCD_BACKUP_PATH, ETCD_VERSION_FILE_NAME)
ETCD_DB_FILE_NAME = 'controller.etcd'
ETCD_BACKUP_FILE_NAME = 'controller.etcd.bck'
ETCD_CONFIG_FILE_PATH = '/etc/default/etcd'
ETCD_CONFIG_CA_FILE = 'caFile'
ETCD_CONFIG_CERT_FILE = 'certFile'
ETCD_CONFIG_KEY_FILE = 'keyFile'
ETCD_CONFIG_ENDPOINTS = 'endpoints'

# etcd versioned directories and symlinks paths
ETCD_VERSIONED_BINARIES_ROOT = '/usr/local/etcd/'
ETCD_SYMLINKS_ROOT = '/var/lib/etcd/'
ETCD_SYMLINKS_STAGE_0 = os.path.join(ETCD_SYMLINKS_ROOT, 'stage0')


def get_cluster_information():
    """Retrieve configured cluster endpoints and certs information
    from the kubeadm-configmap

    :returns: etcd_config: OrderedDict containing cluster information
    """
    etcd_config = {}
    try:
        if utils.is_debian_bullseye():
            newyaml = yaml.YAML()
        else:
            newyaml = YAML()
        kube_operator = kubernetes.KubeOperator()
        configmap_data = kube_operator.kube_read_config_map(
            'kubeadm-config', kubernetes.NAMESPACE_KUBE_SYSTEM)
        stream = StringIO(configmap_data.data['ClusterConfiguration'])
        config = newyaml.load(stream)
        etcd_config = config['etcd']['external']
    except Exception as e:
        LOG.warning('Error retrieving etcd cluster details from kubeadm-config configmap: %s' % e)

    if not etcd_config:
        try:
            with open(ETCD_CONFIG_FILE_PATH, 'r') as file:
                etcd_config_str = file.read()
            if etcd_config_str:
                for line in etcd_config_str.strip().split('\n'):
                    split_line = line.strip().split("=")
                    if split_line[0] == 'ETCD_CERT_FILE':
                        etcd_config.update({ETCD_CONFIG_CERT_FILE: split_line[1].strip('"')})
                    if split_line[0] == 'ETCD_KEY_FILE':
                        etcd_config.update({ETCD_CONFIG_KEY_FILE: split_line[1].strip('"')})
                    if split_line[0] == 'ETCD_TRUSTED_CA_FILE':
                        etcd_config.update({ETCD_CONFIG_CA_FILE: split_line[1].strip('"')})
                    if split_line[0] == 'ETCD_LISTEN_CLIENT_URLS':
                        # Omit https://[127.0.0.1]:2379"
                        endpoint = [split_line[1].strip('"').split(',')[0]]
                        etcd_config.update({ETCD_CONFIG_ENDPOINTS: endpoint})
            else:
                raise exception.SysinvException("Etcd certs and endpoint information not found "
                                                "in %s" % (ETCD_CONFIG_FILE_PATH))
        except Exception as ex:
            raise exception.SysinvException("Error retrieving etcd cluster details from the etcd "
                                            "config file: %s" % (ex))
    return etcd_config


def get_etcd_version_from_symlink():
    """Retrieve current etcd version based on the stage symlink.

    Expecting the following symlink, e.g., for version 3.4.37
    /var/lib/etcd/stage0 -> /usr/local/etcd/3.4.37/stage0

    :returns: etcd_version string
    """
    # Read the etcd stage0 symlink
    try:
        target = os.readlink(ETCD_SYMLINKS_STAGE_0)
    except OSError as ex:
        raise exception.SysinvException(
                "Failed to read symlink %s. Error: %s"
                % (ETCD_SYMLINKS_STAGE_0, ex))

    # Parse the etcd_version from the symlink target
    pattern = r"/usr/local/etcd/(.*)/stage0"
    match = re.search(pattern, target)
    if match is None:
        LOG.error("Unable to find etcd version in symlink target %s" %
                  target)
        return None
    else:
        return match.group(1)


def get_min_etcd_version():
    """Retrieve minimum installed etcd version.

    Determine the minumum version of installed etcd packages under the
    directory: /usr/local/etcd/<version>

    :returns: etcd_version string
    """

    path = ETCD_VERSIONED_BINARIES_ROOT
    directories = []
    try:
        if os.path.isdir(path):
            for entry in os.listdir(path):
                full_path = os.path.join(path, entry)
                if os.path.isdir(full_path):
                    directories.append(entry)
    except Exception as e:
        LOG.error("Failed to get etcd version from: %s, %s." % (path, e))

    etcd_version = min(directories, key=LooseVersion, default=None)
    LOG.debug("Installed etcd version directories: %s, MIN etcd_version = %s"
              % (directories, etcd_version))
    return etcd_version


def get_max_etcd_version():
    """Retrieve maximum installed etcd version.

    Determine the maximum version of installed etcd packages under the
    directory: /usr/local/etcd/<version>

    :returns: etcd_version string
    """

    path = ETCD_VERSIONED_BINARIES_ROOT
    directories = []
    try:
        if os.path.isdir(path):
            for entry in os.listdir(path):
                full_path = os.path.join(path, entry)
                if os.path.isdir(full_path):
                    directories.append(entry)
    except Exception as e:
        LOG.error("Failed to get etcd version from: %s, %s." % (path, e))

    etcd_version = max(directories, key=LooseVersion, default=None)
    LOG.debug("Installed etcd version directories: %s, MAX etcd_version = %s"
              % (directories, etcd_version))
    return etcd_version


def get_installed_etcd_versions():
    """Retrieve list of installed etcd versions.

    Determines the list of installed etcd package versions under the
    directory: /usr/local/etcd/<version>

    :returns: etcd_versions list of string
    """

    path = ETCD_VERSIONED_BINARIES_ROOT
    directories = []
    try:
        if os.path.isdir(path):
            for entry in os.listdir(path):
                full_path = os.path.join(path, entry)
                if os.path.isdir(full_path):
                    directories.append(entry)
    except Exception as e:
        LOG.error("Failed to get etcd version from: %s, %s." % (path, e))

    etcd_versions = sorted(directories, key=LooseVersion)
    LOG.debug("Installed etcd version directories (sorted): %s"
              % (etcd_versions))
    return etcd_versions


def snapshot_etcd(snapshot_file):
    """"Snapshot etcd to a file

    :param snapshot_file: Full path of the snapshot file
    """
    try:
        etcd_config = get_cluster_information()

        ca_cert = etcd_config[ETCD_CONFIG_CA_FILE]
        cert_file = etcd_config[ETCD_CONFIG_CERT_FILE]
        key_file = etcd_config[ETCD_CONFIG_KEY_FILE]
        endpoints = etcd_config[ETCD_CONFIG_ENDPOINTS]
        if len(endpoints) < 1:
            raise exception.SysinvException("Endpoints not found in the etcd cluster details: %s"
                                            % (etcd_config))
        endpoint = endpoints[0]

        snapshot_path = os.path.dirname(snapshot_file)
        if not os.path.exists(snapshot_path):
            os.makedirs(snapshot_path)

        command = ["etcdctl", "--cert", cert_file, "--key", key_file,
        "--cacert", ca_cert, "--endpoints", endpoint, "snapshot", "save",
        snapshot_file]
        proc = subprocess.Popen(command, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=ETCD_API_ENV_VAR)
        try:
            stdout, stderr = proc.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
            LOG.error("Command %s: timed out." % command)
            raise
    except Exception as e:
        LOG.error("Failed to snapshot etcd: %s" % e)
        raise
    if 'Snapshot saved at' in str(stdout):
        LOG.info("Etcd backup successful at %s" % snapshot_file)
    else:
        LOG.error("Failed to save etcd backup with error %s" % stderr)
        raise exception.EtcdOperationFailure(operation=command, error=str(stderr))


def store_etcd_version():
    """"Store current etcd binary version to a backup state file
    """
    try:
        etcd_version = get_etcd_version_from_symlink()

        version_path = os.path.dirname(ETCD_VERSION_FULL_FILE_PATH)
        if not os.path.exists(version_path):
            os.makedirs(version_path)

        # Write the current etcd binary version to backup file
        with open(ETCD_VERSION_FULL_FILE_PATH, "w") as file:
            file.write(etcd_version)
        LOG.info("Write etcd_version %s to %s"
                % (etcd_version, ETCD_VERSION_FULL_FILE_PATH))
    except Exception as ex:
        raise exception.SysinvException(
            "Failed to store etcd binary version: [%s]" % (ex))


def retrieve_etcd_version():
    """Retrieve etcd binary version stored in version state file

    :returns: string: etcd binary version associated with etcd snapshot
    """
    try:
        with open(ETCD_VERSION_FULL_FILE_PATH, "r") as file:
            etcd_version = file.read()
        LOG.info("Read etcd_version %s from %s"
                % (etcd_version, ETCD_VERSION_FULL_FILE_PATH))
    except Exception as ex:
        raise exception.SysinvException(
            "Failed to read etcd version. Error: [%s]" % (ex))
    return etcd_version


def restore_etcd_snapshot(snapshot_file, restore_to_file):
    """"Restore an etcd snapshot

    :param snapshot_file: Full path of the snapshot file
    :param restore_to_file: Full path of the restore to file
    """
    etcd_config = None
    try:
        etcd_config = get_cluster_information()

        ca_cert = etcd_config[ETCD_CONFIG_CA_FILE]
        cert_file = etcd_config[ETCD_CONFIG_CERT_FILE]
        key_file = etcd_config[ETCD_CONFIG_KEY_FILE]
        endpoints = etcd_config[ETCD_CONFIG_ENDPOINTS]
        if len(endpoints) < 1:
            raise exception.SysinvException("Endpoints not found in the etcd cluster details: %s"
                                            % (etcd_config))
        endpoint = endpoints[0]

        restore_path = os.path.dirname(restore_to_file)
        if not os.path.exists(restore_path):
            os.makedirs(restore_path)

        command = ["etcdctl", "--cert", cert_file, "--key", key_file, "--cacert", ca_cert,
                   "--endpoints", endpoint, "snapshot", "restore", snapshot_file, "--data-dir",
                   restore_to_file]
        utils.execute(*command, check_exit_code=0, timeout=60)
    except FileExistsError as ex:
        # Restore file already exists
        raise exception.SysinvException(ex)
    except FileNotFoundError as ex:
        # Snapshot file not found
        raise exception.SysinvException(ex)
    except exception.SysinvException as ex:
        raise ex
    except exception.ProcessExecutionError as ex:
        raise exception.EtcdOperationFailure(operation=command, error=ex)
    except Exception as ex:
        raise exception.SysinvException("Error restoring etcd snapshot: [%s]" % (ex))
