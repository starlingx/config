#
# Copyright (c) 2025-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# All Rights Reserved.
#

""" System Inventory Etcd Utilities and helper functions."""

import json
import os
import re
import socket
import subprocess
import time

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

# Passed explicitly to the one command that sets it. etcdctl defaults to the
# v3 API from etcd 3.4 onward, so the remaining invocations do not need it.
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

# Default etcd client service port.
ETCD_SERVICE_PORT = '2379'

# etcd versioned directories and symlinks paths
ETCD_CA_FILE = '/etc/etcd/ca.crt'
ETCD_CLIENT_CERT = '/etc/etcd/etcd-client.crt'
ETCD_CLIENT_KEY = '/etc/etcd/etcd-client.key'

# Cluster-host names for every member. Present in /etc/hosts on all
# controllers, and correct in every system mode: on simplex both the floating
# and controller-0 names resolve to the same address.
ETCD_CLUSTER_HOST_NAMES = (
    'controller-cluster-host',
    'controller-0-cluster-host',
    'controller-1-cluster-host',
)

# etcdctl's own timeouts are used rather than only a wall-clock bound on the
# subprocess: --dial-timeout bounds reaching the endpoint and --command-timeout
# bounds the operation once connected. Values match those agreed for the
# external migration script so the two sources stay aligned.
#
# etcd is an HA-critical service. A member that has not answered a read within
# a couple of seconds is overloaded rather than slow, so the defaults are short
# and only the operations that genuinely take longer raise them.
ETCDCTL_COMMAND_TIMEOUT = '5s'
ETCDCTL_DIAL_TIMEOUT = '2s'

# Membership changes are committed through raft before the leader replies, and
# a snapshot save streams the whole keyspace.
ETCDCTL_MEMBERSHIP_COMMAND_TIMEOUT = '15s'
ETCDCTL_SNAPSHOT_COMMAND_TIMEOUT = '30s'

# Restoring a snapshot is local and offline: there is no endpoint, so this
# bounds the process rather than an etcdctl command. It is larger than the
# save timeout because the whole keyspace is written to disk.
ETCD_SNAPSHOT_RESTORE_TIMEOUT = 60      # seconds

# Outer bound on the subprocess, so a client that ignores its own timeouts
# cannot hold the conductor greenthread: dial + command + a safety margin.
ETCD_SUBPROCESS_MARGIN = 1


def _seconds(value):
    """Seconds as an int from an etcdctl duration string such as '5s'."""
    return int(value.rstrip('s'))


def subprocess_timeout(command_timeout=ETCDCTL_COMMAND_TIMEOUT):
    """Outer subprocess bound for an etcdctl call."""
    return (_seconds(command_timeout) + _seconds(ETCDCTL_DIAL_TIMEOUT)
            + ETCD_SUBPROCESS_MARGIN)


def etcdctl_timeouts(command_timeout=None, dial_timeout=None):
    """Return timeout flags for etcdctl commands."""
    ct = command_timeout or ETCDCTL_COMMAND_TIMEOUT
    dt = dial_timeout or ETCDCTL_DIAL_TIMEOUT
    return ['--command-timeout', ct, '--dial-timeout', dt]


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


def get_cluster_endpoints_from_db(dbapi, port=ETCD_SERVICE_PORT):
    """Return all etcd cluster endpoints on the cluster-host network.

    Returns the fixed-0, fixed-1 and floating endpoints for the 3-member
    etcd cluster. The fixed instances are addressed by their per-controller
    cluster-host unit IPs; the floating instance uses the floating IP.

    :param dbapi: the database api reference used to resolve addresses.
    :param port: etcd client service port.
    :returns: list of ``https://<addr>:<port>`` endpoint URLs, with IPv6
              addresses formatted per RFC 2732.
    """
    def _address(hostname):
        name = utils.format_address_name(
            hostname, constants.NETWORK_TYPE_CLUSTER_HOST)
        return utils.get_primary_address_by_name(
            dbapi, name, constants.NETWORK_TYPE_CLUSTER_HOST, True).address

    addresses = [
        _address(constants.CONTROLLER_0_HOSTNAME),
        _address(constants.CONTROLLER_1_HOSTNAME),
        _address(constants.CONTROLLER_HOSTNAME),
    ]

    return [
        "https://%s:%s" % (utils.format_url_address(address), port)
        for address in addresses
    ]


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


def get_supported_etcd_version(target_kube_version=None):
    """Retrieve the supported etcd version for a given kubernetes version.

    Determines the correct etcd version by querying the target kubernetes
    version (if provided) or the current kubernetes version, and its
    associated etcd image version, then selecting the highest installed
    etcd binary matching that major.minor.

    :param target_kube_version: target kubernetes version for upgrade
    (e.g. 'v1.33.1'). If None, uses current version from symlink.

    :returns: etcd_version string
    """
    try:
        if target_kube_version:
            kube_version = target_kube_version
        else:
            kube_version = kubernetes.get_kube_version_from_symlink()
        if kube_version:
            kube_ver = kube_version.lstrip('v')

            # Determine the supported etcd major.minor version based on
            # the Kubernetes version and the images configured via kubeadm.
            images = kubernetes.get_k8s_images(kube_ver, include_all=True)
            etcd_image = images.get('etcd', '')
            if etcd_image:
                # etcd image tag format: "registry.k8s.io/etcd:3.5.10-0"
                # Extract version, stripping the trailing build suffix
                tag = etcd_image.split(':')[-1]
                supported_ver = tag.split('-')[0]
                supported_major_minor = LooseVersion(
                    supported_ver).version[:2]

                # Pick the highest installed version whose major.minor
                # does not exceed the kubernetes-expected major.minor
                installed = get_installed_etcd_versions()
                etcd_version = None
                for v in sorted(installed, key=LooseVersion):
                    if LooseVersion(v).version[:2] <= supported_major_minor:
                        etcd_version = v
                if etcd_version:
                    LOG.info("Supported etcd version %s "
                             "(major.minor %s from k8s %s)"
                             % (etcd_version,
                                '.'.join(str(x) for x in supported_major_minor),
                                kube_ver))
                    return etcd_version
    except Exception as e:
        LOG.warning("Unable to determine supported etcd version from "
                    "kubernetes: %s. Falling back to max." % e)

    return get_max_etcd_version()


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

        command = (["etcdctl", "--cert", cert_file, "--key", key_file,
                    "--cacert", ca_cert, "--endpoints", endpoint]
                   + etcdctl_timeouts(ETCDCTL_SNAPSHOT_COMMAND_TIMEOUT)
                   + ["snapshot", "save", snapshot_file])
        proc = subprocess.Popen(command, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=ETCD_API_ENV_VAR)
        try:
            stdout, stderr = proc.communicate(
                timeout=subprocess_timeout(ETCDCTL_SNAPSHOT_COMMAND_TIMEOUT))
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


def _use_etcdutl_for_restore():
    """Determine whether to use etcdutl for snapshot restore.

    Starting from etcd 3.6, 'etcdctl snapshot restore' has been removed.
    The offline tool 'etcdutl snapshot restore' must be used instead.

    :returns: True if etcdutl should be used, False for etcdctl
    """
    etcd_version = get_etcd_version_from_symlink()
    if etcd_version and LooseVersion(etcd_version) >= LooseVersion("3.6.0"):
        return True
    return False


def restore_etcd_snapshot(snapshot_file, restore_to_file):
    """"Restore an etcd snapshot

    :param snapshot_file: Full path of the snapshot file
    :param restore_to_file: Full path of the restore to file
    """
    command = None
    try:
        restore_path = os.path.dirname(restore_to_file)
        if not os.path.exists(restore_path):
            os.makedirs(restore_path)

        if _use_etcdutl_for_restore():
            # etcd 3.6+: use etcdutl (offline utility, no TLS/endpoint flags)
            command = ["etcdutl", "snapshot", "restore", snapshot_file,
                       "--data-dir", restore_to_file]
        else:
            # etcd 3.5 and earlier: use etcdctl with cluster credentials
            etcd_config = get_cluster_information()

            ca_cert = etcd_config[ETCD_CONFIG_CA_FILE]
            cert_file = etcd_config[ETCD_CONFIG_CERT_FILE]
            key_file = etcd_config[ETCD_CONFIG_KEY_FILE]
            endpoints = etcd_config[ETCD_CONFIG_ENDPOINTS]
            if len(endpoints) < 1:
                raise exception.SysinvException(
                    "Endpoints not found in the etcd cluster details: %s"
                    % (etcd_config))
            endpoint = endpoints[0]

            command = ["etcdctl", "--cert", cert_file, "--key", key_file,
                       "--cacert", ca_cert, "--endpoints", endpoint,
                       "snapshot", "restore", snapshot_file,
                       "--data-dir", restore_to_file]
        utils.execute(*command, check_exit_code=0,
                      timeout=ETCD_SNAPSHOT_RESTORE_TIMEOUT)
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


# ============================================================================
# etcd cluster membership management
#
# Architecture (founder-first):
#   The fixed etcd instance on controller-0 (fixed-0) founds the cluster as a
#   single-node seed at bootstrap. Additional members join the running cluster
#   through 'etcdctl member add':
#     - duplex/standard: the DRBD-backed floating instance ('controller')
#     - duplex/standard: the fixed instance on controller-1 (fixed-1)
#   Members are added with --initial-cluster-state=existing.
# ============================================================================

# Loopback is served by the FIXED instance, which lists
# https://127.0.0.1:2379 in its ETCD_LISTEN_CLIENT_URLS. The floating
# instance listens only on the cluster-host floating address, so loopback is
# not a general way to reach the cluster: during an upgrade activate the fixed
# instances are deliberately not started yet and nothing answers on it. Kept
# as the last-resort fallback for when no cluster-host name resolves.
ETCD_LOCAL_ENDPOINT = 'https://127.0.0.1:2379'
ETCD_FIXED_NAME_PREFIX = 'fixed'
ETCD_FLOATING_NAME = 'controller'
ETCD_PORT = 2379
ETCD_PEER_PORT = 2380
ETCD_HEALTH_TIMEOUT = 60      # seconds
ETCD_HEALTH_POLL_INTERVAL = 5  # seconds

# Configured cluster size by system mode. Simplex runs the fixed member
# alone; duplex and standard run fixed-0, fixed-1 and the floating member.
ETCD_MEMBERS_SIMPLEX = 1
ETCD_MEMBERS_DUPLEX = 3

# etcd's own default for --max-learners. Members are therefore added,
# started and promoted one at a time; registering two learners together
# is rejected.
ETCD_MAX_LEARNERS = 1


def _etcdctl_base(endpoint=None, command_timeout=None):
    """Build the common etcdctl argument list for an endpoint."""
    # Resolved here rather than at each call site so every helper reaches the
    # cluster the same way. get_cluster_endpoints() names every member's
    # address and etcdctl tolerates the ones that do not answer.
    if endpoint is None:
        endpoint = get_cluster_endpoints()

    return (['etcdctl', '--endpoints', endpoint]
            + etcdctl_timeouts(command_timeout)
            + ['--cacert', ETCD_CA_FILE,
               '--cert', ETCD_CLIENT_CERT,
               '--key', ETCD_CLIENT_KEY])


def get_members(endpoint=None):
    """Return the etcd cluster members as a list of dicts.

    Each dict carries the raw etcdctl JSON keys: ID, name, peerURLs,
    clientURLs, isLearner.

    :param endpoint: etcd client endpoint to query
    :returns: list of member dicts, empty list on failure
    """
    cmd = _etcdctl_base(endpoint) + ['member', 'list', '-w', 'json']
    try:
        out, _ = utils.execute(*cmd, run_as_root=True,
                               timeout=subprocess_timeout())
        return json.loads(out).get('members', [])
    except Exception as e:
        LOG.warning("Failed to list etcd members via %s: %s", endpoint, e)
        return []


def _member_id(member):
    """Return a member's ID as the hex string etcdctl uses.

    Raises rather than returning a placeholder: the ID is passed to
    promote_member() and member remove, and '0' matches no member, so a
    substituted default would turn a missing ID into an operation against
    nothing.
    """
    member_id = member.get('ID')
    if not member_id:
        raise exception.SysinvException(
            "etcd member %s has no ID" % (member.get('name') or
                                          member.get('peerURLs') or 'unknown'))
    return format(member_id, 'x')


def member_exists(name, peer_url=None, endpoint=None):
    """Return True when the member is already in the cluster.

    Matched on peer URL as well as name. A member that has been registered
    but has not yet started carries no name: etcd only learns the name when
    the member starts and introduces itself, so a member list shows it as
    unstarted with an empty name and its peer URL alone identifying it.

    add_member() registers members as learners by default, which means a
    name-only check reports a freshly added member as absent. The caller then
    concludes the add did not take -- either adding it again, which etcd
    rejects for the duplicate peer URL, or treating the add as failed and
    never starting the member.

    :param name: member name, matched when the member has started
    :param peer_url: member peer URL, which identifies it before it starts
    :param endpoint: etcd client endpoint(s) to query
    """
    return find_member(name, peer_url=peer_url, endpoint=endpoint) is not None


def find_member(name, peer_url=None, endpoint=None):
    """Return the member dict for a member already in the cluster, or None.

    Matched on peer URL as well as name, for the same reason member_exists()
    is: a registered member that has not started carries no name.

    Returning the member rather than a boolean lets add_member() report the
    member ID for a member it finds already registered, which the caller needs
    in order to promote it.

    :param name: member name, matched once the member has started
    :param peer_url: member peer URL, which identifies it before it starts
    :param endpoint: etcd client endpoint(s) to query
    :returns: the member dict, or None when the member is not registered
    """
    for member in get_members(endpoint):
        if name and member.get('name') == name:
            return member
        if peer_url and peer_url in (member.get('peerURLs') or []):
            return member
    return None


def add_member(name, peer_url, endpoint=None, learner=True):
    """Add a member to the running cluster via 'etcdctl member add'.

    Members are added as learners by default. A learner replicates the raft
    log but does not vote, so registering one leaves the quorum requirement
    unchanged. This matters because a member's registration changes the
    quorum requirement the moment it happens rather than when the member
    starts: registering a voter into a cluster of N voters makes the
    requirement (N+1)/2+1 while only N members are running, and for the
    smallest clusters that is immediately fatal. Adding a voter to a
    single-member cluster costs quorum outright until the new member
    starts, taking the leader down with it.

    The caller starts the member and then calls promote_member() once it is
    serving, which is the point at which it begins counting towards quorum.

    Note that etcd permits ETCD_MAX_LEARNERS learners at a time, so members
    must be added, started and promoted one at a time rather than
    registered together.

    Idempotent: returns the existing member ID if the member is already
    registered.

    :param name: member name (for example 'fixed-1' or 'controller')
    :param peer_url: the member's peer URL, https://<addr>:2380
    :param endpoint: an endpoint of the running cluster
    :param learner: add as a non-voting learner (default) or as a voter
    :returns: member ID string
    :raises: SysinvException on failure
    """
    # Matched on peer URL as well as name: a member registered on an earlier
    # pass that has not started yet carries no name, so a name-only check
    # reports it absent and the add is retried, which etcd then rejects for the
    # duplicate peer URL.
    existing = find_member(name, peer_url=peer_url, endpoint=endpoint)
    if existing is not None:
        LOG.info("etcd member '%s' already registered as %s, skipping add",
                 name, _member_id(existing))
        return _member_id(existing)

    cmd = _etcdctl_base(
        endpoint,
        command_timeout=ETCDCTL_MEMBERSHIP_COMMAND_TIMEOUT) + [
        'member', 'add', name, '--peer-urls=%s' % peer_url]
    if learner:
        cmd.append('--learner')
    try:
        utils.execute(*cmd, run_as_root=True,
                      timeout=subprocess_timeout(
                          ETCDCTL_MEMBERSHIP_COMMAND_TIMEOUT))
        LOG.info("Added etcd member '%s'%s with peer URL %s", name,
                 " as a learner" if learner else "", peer_url)
    except Exception as e:
        raise exception.SysinvException(
            "Failed to add etcd member '%s': %s" % (name, e))

    # The member has been registered but has not started, so it has no name
    # yet and can only be found by its peer URL. Checking the name alone here
    # always failed and raised, leaving the caller to conclude the add had not
    # taken: it never started the member, the member never acquired a name and
    # the audit retried indefinitely.
    added = find_member(name, peer_url=peer_url, endpoint=endpoint)
    if added is not None:
        return _member_id(added)

    raise exception.SysinvException(
        "etcd member '%s' with peer URL %s not present after add"
        % (name, peer_url))


def promote_member(name, endpoint=None):
    """Promote a learner to a voting member.

    etcd accepts the promotion only once the learner has caught up with the
    leader, so a successful promotion is also the evidence that the member
    is in sync. This is the point at which the member starts counting
    towards quorum, which is why it is deferred until after the member is
    serving rather than done at registration time.

    Idempotent: a member that already votes is left alone.

    :param name: member name to promote
    :param endpoint: an endpoint of the running cluster
    :raises: SysinvException if the member is absent or cannot be promoted
    """
    member_id = None
    for member in get_members(endpoint):
        if member.get('name') == name:
            if is_voting_member(member):
                LOG.info("etcd member '%s' is already a voter", name)
                return
            member_id = format(member.get('ID', 0), 'x')
            break

    if member_id is None:
        raise exception.SysinvException(
            "etcd member '%s' is not in the cluster, cannot promote" % name)

    cmd = _etcdctl_base(
        endpoint,
        command_timeout=ETCDCTL_MEMBERSHIP_COMMAND_TIMEOUT) + [
        'member', 'promote', member_id]
    try:
        utils.execute(*cmd, run_as_root=True,
                      timeout=subprocess_timeout(
                          ETCDCTL_MEMBERSHIP_COMMAND_TIMEOUT))
        LOG.info("Promoted etcd member '%s' (id %s) to a voting member",
                 name, member_id)
    except Exception as e:
        raise exception.SysinvException(
            "Failed to promote etcd member '%s': %s" % (name, e))


def remove_member(name, peer_url=None, endpoint=None):
    """Remove a member from the cluster, by name or by peer URL.

    The peer URL is accepted because a member that was registered but never
    started carries no name, and those are exactly the members a rollback has
    to clear: a name-only lookup reported them absent, so the removal did
    nothing and left a stale member registered against the cluster.

    Idempotent: does nothing if the member is not in the cluster.

    :param name: member name to remove
    :param peer_url: the member's peer URL, which identifies it before it
                     starts
    :param endpoint: an endpoint of the running cluster
    :raises: SysinvException on failure
    """
    member = find_member(name, peer_url=peer_url, endpoint=endpoint)
    if member is None:
        LOG.info("etcd member '%s' not in cluster, nothing to remove", name)
        return

    member_id = _member_id(member)

    cmd = _etcdctl_base(
        endpoint,
        command_timeout=ETCDCTL_MEMBERSHIP_COMMAND_TIMEOUT) + [
        'member', 'remove', member_id]
    try:
        utils.execute(*cmd, run_as_root=True,
                      timeout=subprocess_timeout(
                          ETCDCTL_MEMBERSHIP_COMMAND_TIMEOUT))
        LOG.info("Removed etcd member '%s' (id %s)", name, member_id)
    except Exception as e:
        raise exception.SysinvException(
            "Failed to remove etcd member '%s': %s" % (name, e))


def is_endpoint_healthy(endpoint):
    """Return True if the given etcd endpoint reports healthy."""
    cmd = _etcdctl_base(endpoint) + ['endpoint', 'health']
    try:
        utils.execute(*cmd, run_as_root=True,
                      timeout=subprocess_timeout())
        return True
    except Exception:
        return False


def wait_for_endpoint(endpoint, timeout=ETCD_HEALTH_TIMEOUT):
    """Poll an endpoint until it is healthy or the timeout elapses.

    :returns: True if the endpoint became healthy, False on timeout
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if is_endpoint_healthy(endpoint):
            return True
        time.sleep(ETCD_HEALTH_POLL_INTERVAL)
    return False


def get_configured_member_count(system_mode):
    """Return the number of etcd members the system is configured for.

    The cluster size follows the system mode rather than the number of
    members currently registered: simplex runs the fixed member alone,
    while duplex and standard run fixed-0, fixed-1 and the floating member.

    Reporting against the configured size is what makes the health alarm
    usable during the procedures that grow or shrink the cluster. While
    membership is deliberately in transition the registered count is not the
    final count, so an alarm keyed to it would assert continuously and gate
    the very steps it exists to protect.

    :param system_mode: the system mode, e.g. 'simplex' or 'duplex'
    :returns: expected member count
    """
    if system_mode == constants.SYSTEM_MODE_SIMPLEX:
        return ETCD_MEMBERS_SIMPLEX
    return ETCD_MEMBERS_DUPLEX


def is_voting_member(member):
    """Whether a member counts towards quorum.

    A learner replicates the log but does not vote, and etcd refuses every
    write and linearizable RPC against one. It is therefore neither able to
    answer a health check nor able to keep the cluster available, and must
    not be reported as healthy.

    :param member: member dict as returned by get_members()
    :returns: True when the member is a voter
    """
    return not member.get('isLearner', False)


def _resolve_name(name):
    """Return the address a cluster-host name resolves to, or None.

    The address is returned rather than the name because the etcd
    certificates carry IP subjectAltNames and no DNS names, so an endpoint
    given as a hostname fails verification:

      x509: certificate is not valid for any names, but wanted to match
            controller-0-cluster-host

    Names that do not resolve are reported as None, which keeps
    unprovisioned or mode-inapplicable controllers out of the endpoint list
    rather than having etcdctl wait on them.
    """
    try:
        info = socket.getaddrinfo(name, None)
    except socket.gaierror:
        return None
    if not info:
        return None
    family, _, _, _, sockaddr = info[0]
    address = sockaddr[0]
    if family == socket.AF_INET6:
        return '[%s]' % address
    return address


def get_cluster_endpoints():
    """Return a comma-separated endpoint list covering every member.

    The health audit must not depend on the local member being up. Querying
    only the loopback endpoint means that when the local member is the one
    that has failed, the member list comes back empty and the cluster appears
    entirely down -- reporting nothing healthy and naming no failed member,
    which is the least useful answer at exactly the moment it matters most.

    etcdctl accepts a list of endpoints for a member list and tolerates
    entries that do not answer, so naming every controller lets the audit see
    the cluster through whichever members remain. Names that do not resolve
    are skipped, which keeps the list correct on simplex and during the window
    before a controller has been provisioned.
    """
    # Deduplicated: on simplex the floating and controller-0 names resolve to
    # the same address, and listing it twice would have etcdctl weigh one
    # member twice.
    addresses = []
    for name in ETCD_CLUSTER_HOST_NAMES:
        address = _resolve_name(name)
        if address and address not in addresses:
            addresses.append(address)

    endpoints = ['https://%s:%s' % (utils.format_url_address(a), ETCD_PORT)
                 for a in addresses]

    if not endpoints:
        LOG.warning("No cluster-host name resolved; falling back to %s for "
                    "the etcd cluster health query", ETCD_LOCAL_ENDPOINT)
        return ETCD_LOCAL_ENDPOINT

    return ','.join(endpoints)


def get_cluster_health(endpoint=None, system_mode=None):
    """Return (healthy_count, total_count, unhealthy_names) for the cluster.

    A member is counted healthy when it is a voting member and its
    advertised client endpoint responds to an endpoint-health check. A
    learner is never counted healthy: it does not contribute to quorum, and
    etcd rejects the health RPC against it regardless.

    total_count is the number of members the system is configured for, not
    the number currently registered, so that the count remains stable while
    membership is being changed.

    :param endpoint: etcd client endpoint(s) to query; when omitted every
                     member's cluster-host endpoint is used
    :param system_mode: system mode used to derive the configured size;
                        when omitted the registered count is used
    """
    if endpoint is None:
        endpoint = get_cluster_endpoints()

    if system_mode is None:
        total = None
    else:
        total = get_configured_member_count(system_mode)

    members = get_members(endpoint)
    if not members:
        return 0, total or 0, []

    healthy = 0
    unhealthy = []
    for member in members:
        name = member.get('name') or '<unnamed>'

        if not is_voting_member(member):
            # Named separately from an unreachable member: a learner is
            # reachable but cannot vote, and needs promoting rather than
            # recovering.
            unhealthy.append("%s (learner)" % name)
            continue

        client_urls = member.get('clientURLs') or []
        if not client_urls:
            unhealthy.append(name)
            continue
        if is_endpoint_healthy(client_urls[0]):
            healthy += 1
        else:
            unhealthy.append(name)

    if total is None:
        total = len(members)

    # A member that should exist but was never registered is missing rather
    # than unhealthy; report it so the count and the names agree.
    missing = total - len(members)
    if missing > 0:
        unhealthy.append("%d member(s) not registered" % missing)

    return healthy, total, unhealthy
